package passwordless

import (
	"sync"
	"time"

	"github.com/pzduniak/mcf"
	"golang.org/x/net/context"
)

// MemStore is a Store that keeps tokens in memory, expiring them periodically
// when they expire.
type MemStore struct {
	mut         sync.Mutex
	data        map[string]memToken
	cleaner     *time.Ticker
	quitCleaner chan (struct{})
}

type memToken struct {
	UID         string
	HashedToken []byte
	Expires     time.Time
}

// NewMemStore creates and returns a new `MemStore`
func NewMemStore() *MemStore {
	ct := time.NewTicker(time.Second)
	ms := &MemStore{
		data:        make(map[string]memToken),
		quitCleaner: make(chan struct{}),
		cleaner:     ct,
	}
	// Run cleaner periodically
	go func(quit chan struct{}) {
	ticker:
		for {
			select {
			case <-ct.C:
				// Run clean cycle
				ms.Clean()
			case <-quit:
				// Release resources
				ct.Stop()
				break ticker
			}
		}
	}(ms.quitCleaner)
	return ms
}

func (s *MemStore) Store(ctx context.Context, token, uid string,
	ttl time.Duration) error {
	hashToken, err := mcf.Create([]byte(token))
	if err != nil {
		return err
	}

	s.mut.Lock()
	defer s.mut.Unlock()
	s.data[uid] = memToken{
		UID:         uid,
		HashedToken: hashToken,
		Expires:     time.Now().Add(ttl),
	}

	return nil
}

func (s *MemStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	if t, ok := s.data[uid]; !ok {
		// No known token for this user
		return false, time.Time{}, nil
	} else if time.Now().After(t.Expires) {
		// Token exists, but expired
		return false, time.Time{}, nil
	} else {
		// Token exists and is still valid
		return true, t.Expires, nil
	}
}

func (s *MemStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	if t, ok := s.data[uid]; !ok {
		// No token in database
		return false, ErrTokenNotFound
	} else if time.Now().After(t.Expires) {
		// Token exists but has expired
		return false, ErrTokenNotFound
	} else if valid, err := mcf.Verify([]byte(token), t.HashedToken); err != nil {
		// Couldn't validate token
		return false, err
	} else if !valid {
		// Token does not validate against hashed token
		return false, nil
	} else {
		// Token is valid!
		return true, nil
	}
}

func (s *MemStore) Delete(ctx context.Context, uid string) error {
	s.mut.Lock()
	defer s.mut.Unlock()
	delete(s.data, uid)
	return nil
}

// Clean removes expired entries from the store.
func (s *MemStore) Clean() {
	s.mut.Lock()
	defer s.mut.Unlock()
	for uid, token := range s.data {
		if time.Now().After(token.Expires) {
			delete(s.data, uid)
		}
	}
}

// Release disposes of the MemStore and any released resources
func (s *MemStore) Release() {
	s.cleaner.Stop()
	close(s.quitCleaner)
	s.data = nil
}
