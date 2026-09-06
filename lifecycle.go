package main

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var _ pluginapi.RequestLifecyclePlugin = (*privacyFilterPlugin)(nil)

// HandleRequestComplete removes the mapping table of a finished request. The
// host sends exactly one completion per request that reached interception,
// asynchronously and after the response or the last stream chunk has been
// delivered, so nothing on the return path still needs the table. Expired
// tables of requests whose completion never arrives are dropped by the
// store itself on every Put, so no sweep is needed here.
func (p *privacyFilterPlugin) HandleRequestComplete(ctx context.Context, done pluginapi.RequestCompletion) error {
	if p.store == nil || done.RequestID == "" {
		return nil
	}
	if p.audit != nil {
		table, err := p.store.Get(done.RequestID)
		if err != nil {
			table = nil
		}
		p.audit.complete(done.RequestID, done, table)
	}
	p.store.Delete(done.RequestID)
	if p.streams != nil {
		p.streams.finish(done.RequestID, done.Stream)
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"outcome": string(done.Outcome),
			"stream":  done.Stream,
			"tables":  p.store.Len(),
		}).Debug("privacyfilter: mapping table released")
	}
	return nil
}
