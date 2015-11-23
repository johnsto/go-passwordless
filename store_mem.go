package passwordless

import (
	"sync"
	"time"

	"github.com/gyepisam/mcf"
	"golang.org/x/net/context"
)

type MemStore struct {
	mut         sync.Mutex
	data        map[string]Token
	cleaner     *time.Ticker
	quitCleaner chan (struct{})
}

func NewMemStore() *MemStore {
	ct := time.NewTicker(time.Minute)
	ms := &MemStore{
		data:    make(map[string]Token),
		cleaner: ct,
	}
	// Run cleaner periodically
	go func() {
	ticker:
		for {
			select {
			case <-ct.C:
				// Run clean cycle
				ms.Clean()
			case <-ms.quitCleaner:
				// Release resources
				ct.Stop()
				break ticker
			}
		}
	}()
	return ms
}

func (s *MemStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	hashToken, err := mcf.Create(token)
	if err != nil {
		return err
	}

	s.mut.Lock()
	defer s.mut.Unlock()
	s.data[uid] = Token{
		UID:         uid,
		HashedToken: hashToken,
		Expires:     time.Now().Add(ttl),
	}

	return nil
}

func (s *MemStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	if t, ok := s.data[uid]; !ok {
		// No token in database
		return false, ErrTokenNotFound
	} else if time.Now().After(t.Expires) {
		// Token exists but has expired
		return false, ErrTokenExpired
	} else if valid, err := mcf.Verify(token, t.HashedToken); err != nil {
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
	s.quitCleaner <- struct{}{}
	s.data = nil
}