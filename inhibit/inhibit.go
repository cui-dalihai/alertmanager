// Copyright 2015 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inhibit

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/store"
	"github.com/prometheus/alertmanager/types"
)

// An Inhibitor determines whether a given label set is muted based on the
// currently active alerts and a set of inhibition rules. It implements the
// Muter interface.
type Inhibitor struct {
	alerts provider.Alerts
	rules  []*InhibitRule
	marker types.Marker
	logger log.Logger

	mtx    sync.RWMutex
	cancel func()
}

// NewInhibitor returns a new Inhibitor.
func NewInhibitor(ap provider.Alerts, rs []*config.InhibitRule, mk types.Marker, logger log.Logger) *Inhibitor {
	ih := &Inhibitor{
		alerts: ap,
		marker: mk,
		logger: logger,
	}
	for _, cr := range rs {
		r := NewInhibitRule(cr)
		ih.rules = append(ih.rules, r)
	}
	return ih
}

// Inhibitor和Dispatcher一样也会 Subscribe AlertProvider
//
func (ih *Inhibitor) run(ctx context.Context) {
	it := ih.alerts.Subscribe()
	defer it.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case a := <-it.Next():
			if err := it.Err(); err != nil {
				level.Error(ih.logger).Log("msg", "Error iterating alerts", "err", err)
				continue
			}
			// Update the inhibition rules' cache.
			// 对于一个新的 alert, 如果发现满足 inhibit rule 的 source 侧, 那么
			// 就缓存这个 alert, 因为它可能够抑制其他 alert
			for _, r := range ih.rules {
				if r.SourceMatchers.Matches(a.Labels) {
					if err := r.scache.Set(a); err != nil {
						level.Error(ih.logger).Log("msg", "error on set alert", "err", err)
					}
				}
			}
		}
	}
}

// Run the Inhibitor's background processing.
func (ih *Inhibitor) Run() {
	var (
		g   run.Group
		ctx context.Context
	)

	ih.mtx.Lock()
	ctx, ih.cancel = context.WithCancel(context.Background())
	ih.mtx.Unlock()
	runCtx, runCancel := context.WithCancel(ctx)

	for _, rule := range ih.rules {
		go rule.scache.Run(runCtx, 15*time.Minute)
	}

	g.Add(func() error {
		ih.run(runCtx)
		return nil
	}, func(err error) {
		runCancel()
	})

	if err := g.Run(); err != nil {
		level.Warn(ih.logger).Log("msg", "error running inhibitor", "err", err)
	}
}

// Stop the Inhibitor's background processing.
func (ih *Inhibitor) Stop() {
	if ih == nil {
		return
	}

	ih.mtx.RLock()
	defer ih.mtx.RUnlock()
	if ih.cancel != nil {
		ih.cancel()
	}
}

// Mutes returns true iff the given label set is muted. It implements the Muter
// interface.
func (ih *Inhibitor) Mutes(lset model.LabelSet) bool {
	fp := lset.Fingerprint()

	// 检查内存中所有 rule 是否匹配 lset
	for _, r := range ih.rules {

		// target 不匹配就没必要计算了, 因为我们就是为了抑制 target
		if !r.TargetMatchers.Matches(lset) {
			// If target side of rule doesn't match, we don't need to look any further.
			continue
		}
		// If we are here, the target side matches. If the source side matches, too, we
		// need to exclude inhibiting alerts for which the same is true.
		// target 匹配就检查 source, 如果 source 也匹配, 那么就需要排除两端都匹配的情况
		//
		if inhibitedByFP, eq := r.hasEqual(lset, r.SourceMatchers.Matches(lset)); eq {
			ih.marker.SetInhibited(fp, inhibitedByFP.String())
			return true
		}
	}
	ih.marker.SetInhibited(fp)

	return false
}

// An InhibitRule specifies that a class of (source) alerts should inhibit
// notifications for another class of (target) alerts if all specified matching
// labels are equal between the two alerts. This may be used to inhibit alerts
// from sending notifications if their meaning is logically a subset of a
// higher-level alert.
type InhibitRule struct {
	// The set of Filters which define the group of source alerts (which inhibit
	// the target alerts).
	SourceMatchers labels.Matchers
	// The set of Filters which define the group of target alerts (which are
	// inhibited by the source alerts).
	TargetMatchers labels.Matchers
	// A set of label names whose label values need to be identical in source and
	// target alerts in order for the inhibition to take effect.
	Equal map[model.LabelName]struct{}

	// Cache of alerts matching source labels.
	// 内存缓存了所有匹配 source 的告警
	// 方便后面使用这些告警来抑制出现的 target
	scache *store.Alerts
}

// NewInhibitRule returns a new InhibitRule based on a configuration definition.
func NewInhibitRule(cr *config.InhibitRule) *InhibitRule {
	var (
		sourcem labels.Matchers
		targetm labels.Matchers
	)
	// cr.SourceMatch will be deprecated. This for loop appends regex matchers.
	for ln, lv := range cr.SourceMatch {
		matcher, err := labels.NewMatcher(labels.MatchEqual, ln, lv)
		if err != nil {
			// This error must not happen because the config already validates the yaml.
			panic(err)
		}
		sourcem = append(sourcem, matcher)
	}
	// cr.SourceMatchRE will be deprecated. This for loop appends regex matchers.
	for ln, lv := range cr.SourceMatchRE {
		matcher, err := labels.NewMatcher(labels.MatchRegexp, ln, lv.String())
		if err != nil {
			// This error must not happen because the config already validates the yaml.
			panic(err)
		}
		sourcem = append(sourcem, matcher)
	}
	// We append the new-style matchers. This can be simplified once the deprecated matcher syntax is removed.
	sourcem = append(sourcem, cr.SourceMatchers...)

	// cr.TargetMatch will be deprecated. This for loop appends regex matchers.
	for ln, lv := range cr.TargetMatch {
		matcher, err := labels.NewMatcher(labels.MatchEqual, ln, lv)
		if err != nil {
			// This error must not happen because the config already validates the yaml.
			panic(err)
		}
		targetm = append(targetm, matcher)
	}
	// cr.TargetMatchRE will be deprecated. This for loop appends regex matchers.
	for ln, lv := range cr.TargetMatchRE {
		matcher, err := labels.NewMatcher(labels.MatchRegexp, ln, lv.String())
		if err != nil {
			// This error must not happen because the config already validates the yaml.
			panic(err)
		}
		targetm = append(targetm, matcher)
	}
	// We append the new-style matchers. This can be simplified once the deprecated matcher syntax is removed.
	targetm = append(targetm, cr.TargetMatchers...)

	equal := map[model.LabelName]struct{}{}
	for _, ln := range cr.Equal {
		equal[ln] = struct{}{}
	}

	return &InhibitRule{
		SourceMatchers: sourcem,
		TargetMatchers: targetm,
		Equal:          equal,
		scache:         store.NewAlerts(),
	}
}

// hasEqual checks whether the source cache contains alerts matching the equal
// labels for the given label set. If so, the fingerprint of one of those alerts
// is returned. If excludeTwoSidedMatch is true, alerts that match both the
// source and the target side of the rule are disregarded.

// 调用这个函数之前, 被检查 alert 已经满足了规则的 target,
// 而规则中 scache 的 alert 已经满足了规则的 source
// 剩下要确认的是:
// 		scache 中的 alert 有没有标签和被检查 alert 标签一致的,
//		再避免 alert 自我抑制的场景就可以了
func (r *InhibitRule) hasEqual(lset model.LabelSet, excludeTwoSidedMatch bool) (model.Fingerprint, bool) {
Outer:
	for _, a := range r.scache.List() {
		// The cache might be stale and contain resolved alerts.
		if a.Resolved() {
			continue
		}

		// 检查规则标签
		for n := range r.Equal {
			if a.Labels[n] != lset[n] {
				continue Outer
			}
		}
		// a 在加入 r.scache 的时候已经满足了 r.Source, 如果再通过 target 检查, 那么 scache 中的这个 a 同时满足 source 和 target
		// 而 excludeTwoSidedMatch 如果为 true, 表示当前 dispatcher 处理的 alert 在 source 和 target 都满足
		// 所以这个条件变成了: 如果 a 和被检查的 alert 同时满足 source 和 target, 而且被检查的标签还满足规则生效的条件
		// 就忽略 a 对被检查 alert 的抑制,
		// 这里防止了一个告警自己抑制自己情况
		if excludeTwoSidedMatch && r.TargetMatchers.Matches(a.Labels) {
			continue Outer
		}
		return a.Fingerprint(), true
	}
	return model.Fingerprint(0), false
}
