// Copyright 2016 Prometheus Team
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

package mem

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/store"
	"github.com/prometheus/alertmanager/types"
)

const alertChannelLength = 200

// Alerts gives access to a set of alerts. All methods are goroutine-safe.
// alerts 管理结构, 就是架构图中的 AlertsProvider
type Alerts struct {
	cancel context.CancelFunc

	mtx       sync.Mutex
	alerts    *store.Alerts	 			// 存储结构
	listeners map[int]listeningAlerts	// 正在激活的alert
	next      int

	callback AlertStoreCallback

	logger log.Logger
}

type AlertStoreCallback interface {
	// PreStore is called before alert is stored into the store. If this method returns error,
	// alert is not stored.
	// Existing flag indicates whether alert has existed before (and is only updated) or not.
	// If alert has existed before, then alert passed to PreStore is result of merging existing alert with new alert.
	PreStore(alert *types.Alert, existing bool) error

	// PostStore is called after alert has been put into store.
	PostStore(alert *types.Alert, existing bool)

	// PostDelete is called after alert has been removed from the store due to alert garbage collection.
	PostDelete(alert *types.Alert)
}

// 上面 AlertsProvider 中使用map来管理多个 listeningAlerts
type listeningAlerts struct {
	alerts chan *types.Alert // alert chan
	done   chan struct{}     // 当前的 listeningAlerts 是否已经结束
}

// NewAlerts returns a new alert provider.
func NewAlerts(ctx context.Context, m types.Marker, intervalGC time.Duration, alertCallback AlertStoreCallback, l log.Logger) (*Alerts, error) {
	if alertCallback == nil {
		alertCallback = noopCallback{}
	}

	ctx, cancel := context.WithCancel(ctx)
	a := &Alerts{
		alerts:    store.NewAlerts(),
		cancel:    cancel,
		listeners: map[int]listeningAlerts{},
		next:      0,
		logger:    log.With(l, "component", "provider"),
		callback:  alertCallback,
	}

	// 注册一个回调函数用来清理 AlertsProvider 中已经完成的listener
	a.alerts.SetGCCallback(func(alerts []*types.Alert) {
		for _, alert := range alerts {
			// As we don't persist alerts, we no longer consider them after
			// they are resolved. Alerts waiting for resolved notifications are
			// held in memory in aggregation groups redundantly.
			m.Delete(alert.Fingerprint())
			a.callback.PostDelete(alert)
		}

		a.mtx.Lock()
		for i, l := range a.listeners {
			select {
			case <-l.done:
				delete(a.listeners, i)
				close(l.alerts)
			default:
				// listener is not closed yet, hence proceed.
			}
		}
		a.mtx.Unlock()
	})
	go a.alerts.Run(ctx, intervalGC)

	return a, nil
}

// Close the alert provider.
func (a *Alerts) Close() {
	if a.cancel != nil {
		a.cancel()
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Subscribe returns an iterator over active alerts that have not been
// resolved and successfully notified about.
// They are not guaranteed to be in chronological order.
// 这个 Subscribe 方法是 Dispatcher 用来订阅 AlertProvider
// 先把当前 AlertProvider 中所有的 Alerts 放在一个 Buffered chan 中, 然后再把这个 Buffered chan 放到 AlertProvider 的 listeners 中
// 然后再把这个 Buffered chan 包装成 NewAlertIterator 返回, Dispatcher 会通过 NewAlertIterator 的 Next 方法获取这个 Buffered chan
// 并使用 for...select 来监听这个chan, 而 AlertProvider 每次收到一个 Alert, 即调用 Put 方法, 就会遍历自己的 listeners , 把新的 Alert
// 发送给每一个 listener 的 Buffered chan.
// 这样就实现了 Dispatcher 订阅 AlertProvider, AlertProvider 收到新的 Alert 通知所有订阅者的结构
func (a *Alerts) Subscribe() provider.AlertIterator {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	var (
		done   = make(chan struct{})
		alerts = a.alerts.List()                                               // 获取所有的alerts
		ch     = make(chan *types.Alert, max(len(alerts), alertChannelLength)) // 创建一个 buffer chan, 保证容量要么盈余, 要么恰好
	)

	for _, a := range alerts {
		ch <- a
	}

	// 为 AlertsProvider 新建一个 listener, 所以调用 Subscribe 会为当前所有的 alerts 创建一个 listener
	a.listeners[a.next] = listeningAlerts{alerts: ch, done: done}
	a.next++

	return provider.NewAlertIterator(ch, done, nil)
}

// GetPending returns an iterator over all the alerts that have
// pending notifications.
func (a *Alerts) GetPending() provider.AlertIterator {
	var (
		ch   = make(chan *types.Alert, alertChannelLength)
		done = make(chan struct{})
	)

	go func() {
		defer close(ch)

		for _, a := range a.alerts.List() {
			select {
			case ch <- a:
			case <-done:
				return
			}
		}
	}()

	return provider.NewAlertIterator(ch, done, nil)
}

// Get returns the alert for a given fingerprint.
func (a *Alerts) Get(fp model.Fingerprint) (*types.Alert, error) {
	return a.alerts.Get(fp)
}

// Put adds the given alert to the set.
// 是把新建的 alerts 存放到 AlertsProvider 中
func (a *Alerts) Put(alerts ...*types.Alert) error {
	for _, alert := range alerts {
		fp := alert.Fingerprint() // 制作唯一ID, 基于 alerts 的 LabelSets

		existing := false

		// Check that there's an alert existing within the store before
		// trying to merge.
		// 如果已经存在相同的alert, 就是labelSets相同
		if old, err := a.alerts.Get(fp); err == nil {
			existing = true

			// Merge alerts if there is an overlap in activity range.
			// 新旧告警区间有重叠的, 合并
			if (alert.EndsAt.After(old.StartsAt) && alert.EndsAt.Before(old.EndsAt)) ||
				(alert.StartsAt.After(old.StartsAt) && alert.StartsAt.Before(old.EndsAt)) {
				alert = old.Merge(alert)
			}
		}

		if err := a.callback.PreStore(alert, existing); err != nil {
			level.Error(a.logger).Log("msg", "pre-store callback returned error on set alert", "err", err)
			continue
		}

		if err := a.alerts.Set(alert); err != nil {
			level.Error(a.logger).Log("msg", "error on set alert", "err", err)
			continue
		}

		a.callback.PostStore(alert, existing)

		a.mtx.Lock()

		// 尝试写入 AlertsProvider 中的 listeners
		// 由于每个 Dispatcher Subscribe AlertProvider 的时候都会新建一个 listener
		// 所以每次 put 一个 alert 时都要发给所有的 listener
		// 而每个 Dispatcher
		for _, l := range a.listeners {
			select {
			case l.alerts <- alert:
			case <-l.done:
			}
		}
		a.mtx.Unlock()
	}

	return nil
}

type noopCallback struct{}

func (n noopCallback) PreStore(_ *types.Alert, _ bool) error { return nil }
func (n noopCallback) PostStore(_ *types.Alert, _ bool)      {}
func (n noopCallback) PostDelete(_ *types.Alert)             {}
