package portrait

import (
	"Threshold/pkg/storage"

	"Threshold/pkg/types"
)

type Store struct {
	store storage.Store
}

func NewStore(store storage.Store) *Store {

	return &Store{store: store}
}

func (s *Store) IsBlacklisted(deviceUUID string) bool {

	val := false

	s.store.View(func(tx storage.Tx) error {

		v, err := tx.Get(storage.BucketBlacklist, []byte(deviceUUID))

		if err == nil && v != nil {
			val = true
		}

		return nil

	})

	return val
}

func (s *Store) GetHistory(userID string, limit int) []*types.ConnectionSummary {

	return nil
}

func (s *Store) AppendSummary(userID string, summary *types.ConnectionSummary) error {

	return nil
}

func (s *Store) BlacklistDevice(deviceUUID string, reason string) error {

	return s.store.Update(func(tx storage.Tx) error {

		return tx.Put(storage.BucketBlacklist, []byte(deviceUUID), []byte(reason))

	})
}

func (s *Store) OnConnectionClose(ctx *types.ConnectionContext) error {

	return nil
}
