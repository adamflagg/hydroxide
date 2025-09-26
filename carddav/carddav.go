package carddav

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"
	"github.com/emersion/hydroxide/protonmail"
)

// TODO: use a HTTP error
var errNotFound = errors.New("carddav: not found")

var (
	cleartextCardProps = []string{vcard.FieldVersion, vcard.FieldProductID, "X-PM-LABEL", "X-PM-GROUP"}
	signedCardProps    = []string{vcard.FieldVersion, vcard.FieldProductID, vcard.FieldFormattedName, vcard.FieldUID, vcard.FieldEmail}
)

var addressBook = &carddav.AddressBook{
	Path:            "/principal/contacts/default/",
	Name:            "ProtonMail",
	Description:     "ProtonMail contacts",
	MaxResourceSize: 100 * 1024,
}

// generateUID creates a simple UUID for contact identification
func generateUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("hydroxide-%08x-%04x-%04x-%04x-%012x", 
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func formatCard(card vcard.Card, privateKey *openpgp.Entity) (*protonmail.ContactImport, error) {
	vcard.ToV4(card)

	// Ensure the card has a UID, generate one if missing
	if _, hasUID := card[vcard.FieldUID]; !hasUID {
		uid := generateUID()
		log.Printf("debug: Generated UID for contact: %s", uid)
		card.Add(vcard.FieldUID, &vcard.Field{Value: uid})
	}

	// Add groups to emails - ensure each email has a unique group
	// First, collect all existing group numbers to avoid collisions
	existingGroups := make(map[string]bool)
	for _, fields := range card {
		for _, field := range fields {
			if field.Group != "" && strings.HasPrefix(field.Group, "item") {
				existingGroups[field.Group] = true
			}
		}
	}

	// Find the next available item number
	nextItemNum := 1
	for {
		groupName := "item" + strconv.Itoa(nextItemNum)
		if !existingGroups[groupName] {
			break
		}
		nextItemNum++
	}

	// Assign groups to emails that don't have them
	for _, email := range card[vcard.FieldEmail] {
		if email.Group == "" {
			email.Group = "item" + strconv.Itoa(nextItemNum)
			existingGroups[email.Group] = true
			nextItemNum++
		}
	}

	toEncrypt := card
	toSign := make(vcard.Card)
	for _, k := range signedCardProps {
		if fields, ok := toEncrypt[k]; ok {
			toSign[k] = fields
			if k != vcard.FieldVersion {
				delete(toEncrypt, k)
			}
		}
	}

	var contactImport protonmail.ContactImport
	var b bytes.Buffer

	if len(toSign) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toSign); err != nil {
			return nil, err
		}
		signed, err := protonmail.NewSignedContactCard(&b, privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, signed)
		b.Reset()
	}

	if len(toEncrypt) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toEncrypt); err != nil {
			return nil, err
		}
		to := []*openpgp.Entity{privateKey}
		encrypted, err := protonmail.NewEncryptedContactCard(&b, to, privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, encrypted)
		b.Reset()
	}

	return &contactImport, nil
}

func parseAddressObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/principal/contacts/default/" || ext != ".vcf" {
		return "", errNotFound
	}
	return strings.TrimSuffix(filename, ext), nil
}

func formatAddressObjectPath(id string) string {
	return "/principal/contacts/default/" + id + ".vcf"
}

func (b *backend) toAddressObject(contact *protonmail.Contact, req *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	// TODO: handle req

	// Reduced logging - only log on errors or unusual cases
	
	card := make(vcard.Card)
	for i, c := range contact.Cards {
		// Use optimized keyring with only main account key for CardDAV
		md, err := c.Read(b.cardDAVKeyring)
		if err != nil {
			log.Printf("error: failed to decrypt card %d for contact %s: %v", i+1, contact.ID, err)
			return nil, err
		}

		decoded, err := vcard.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			log.Printf("error: failed to decode vcard %d for contact %s: %v", i+1, contact.ID, err)
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
		io.Copy(ioutil.Discard, md.UnverifiedBody)
		if err := md.SignatureError; err != nil {
			log.Printf("error: signature error for card %d of contact %s: %v", i+1, contact.ID, err)
			return nil, err
		}

		for k, fields := range decoded {
			for _, f := range fields {
				card.Add(k, f)
			}
		}
		// Card processed successfully - no need to log unless debugging specific issues
	}

	return &carddav.AddressObject{
		Path:    formatAddressObjectPath(contact.ID),
		ModTime: contact.ModifyTime.Time(),
		// TODO: stronger ETag
		ETag: fmt.Sprintf("%x%x", contact.ModifyTime, contact.Size),
		Card: card,
	}, nil
}

type backend struct {
	c              *protonmail.Client
	cache          map[string]*protonmail.Contact
	locker         sync.Mutex
	total          int
	privateKeys    openpgp.EntityList
	mainAccountKey *openpgp.Entity
	cardDAVKeyring openpgp.EntityList // Optimized keyring with only main account key
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	log.Printf("debug: CurrentUserPrincipal called, returning '/principal/'")
	return "/principal/", nil
}

func (b *backend) AddressBookHomeSetPath(ctx context.Context) (string, error) {
	log.Printf("debug: AddressBookHomeSetPath called, returning '/principal/contacts/'")
	return "/principal/contacts/", nil
}

func (b *backend) CreateAddressBook(ctx context.Context, ab *carddav.AddressBook) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new address book"))
}

func (b *backend) DeleteAddressBook(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot delete address book"))
}

func (b *backend) ListAddressBooks(ctx context.Context) ([]carddav.AddressBook, error) {
	log.Printf("debug: ListAddressBooks called")
	return []carddav.AddressBook{*addressBook}, nil
}

func (b *backend) GetAddressBook(ctx context.Context, reqPath string) (*carddav.AddressBook, error) {
	log.Printf("debug: GetAddressBook called for path: %s", reqPath)
	
	// Clean the path
	cleanPath := path.Clean(reqPath)
	
	// Handle both canonical and non-canonical collection paths for WebDAV compatibility
	if cleanPath == "/principal/contacts/default" || cleanPath == "/principal/contacts/default/" {
		log.Printf("debug: Address book found, returning addressBook")
		return addressBook, nil
	}
	
	log.Printf("debug: Address book not found for path: %s", cleanPath)
	return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("address book not found"))
}

func (b *backend) cacheComplete() bool {
	b.locker.Lock()
	defer b.locker.Unlock()
	return b.total >= 0 && len(b.cache) == b.total
}

func (b *backend) getCache(id string) (*protonmail.Contact, bool) {
	b.locker.Lock()
	contact, ok := b.cache[id]
	b.locker.Unlock()
	return contact, ok
}

func (b *backend) putCache(contact *protonmail.Contact) {
	b.locker.Lock()
	b.cache[contact.ID] = contact
	b.locker.Unlock()
}

func (b *backend) deleteCache(id string) {
	b.locker.Lock()
	delete(b.cache, id)
	b.locker.Unlock()
}

func (b *backend) GetAddressObject(ctx context.Context, path string, req *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return nil, err
	}

	contact, ok := b.getCache(id)
	if !ok {
		if b.cacheComplete() {
			return nil, errNotFound
		}

		contact, err = b.c.GetContact(id)
		if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 13051 {
			return nil, errNotFound
		} else if err != nil {
			return nil, err
		}
		b.putCache(contact)
	}

	return b.toAddressObject(contact, req)
}

func (b *backend) ListAddressObjects(ctx context.Context, path string, req *carddav.AddressDataRequest) ([]carddav.AddressObject, error) {
	log.Printf("debug: ListAddressObjects called for path: %s", path)
	
	// Add timeout to prevent hanging on network issues
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	if b.cacheComplete() {
		log.Printf("debug: Using cached contacts (%d items)", len(b.cache))
		b.locker.Lock()
		defer b.locker.Unlock()

		aos := make([]carddav.AddressObject, 0, len(b.cache))
		for _, contact := range b.cache {
			ao, err := b.toAddressObject(contact, req)
			if err != nil {
				log.Printf("warning: failed to process cached contact %s: %v", contact.ID, err)
				continue // Skip this contact instead of failing entirely
			}
			aos = append(aos, *ao)
		}

		log.Printf("debug: Returning %d cached address objects", len(aos))
		return aos, nil
	}

	// Get a list of all contacts
	// TODO: paging support
	log.Printf("debug: Fetching contact list from server...")
	total, contacts, err := b.c.ListContacts(0, 0)
	if err != nil {
		// Check if this was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("error: ListContacts timed out after 30 seconds")
		}
		log.Printf("error: ListContacts failed: %v", err)
		return nil, err
	}
	log.Printf("debug: Found %d contacts (metadata)", total)
	
	b.locker.Lock()
	b.total = total
	b.locker.Unlock()

	m := make(map[string]*protonmail.Contact, total)
	for _, contact := range contacts {
		m[contact.ID] = contact
	}

	// Get all contacts cards
	aos := make([]carddav.AddressObject, 0, total)
	page := 0
	failedContacts := 0
	maxPages := 100 // Safety limit to prevent infinite loops
	for page < maxPages {
		log.Printf("debug: Fetching contact export page %d...", page)
		_, contacts, err := b.c.ListContactsExport(page, 0)
		if err != nil {
			// Check if this was a timeout
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("error: ListContactsExport timed out after 30 seconds on page %d", page)
			}
			log.Printf("error: ListContactsExport failed on page %d: %v", page, err)
			return nil, err
		}
		log.Printf("debug: Got %d contacts in export page %d", len(contacts), page)

		for _, contactExport := range contacts {
			contact, ok := m[contactExport.ID]
			if !ok {
				log.Printf("warning: contact export %s not found in metadata", contactExport.ID)
				continue
			}
			contact.Cards = contactExport.Cards
			b.putCache(contact)

			ao, err := b.toAddressObject(contact, req)
			if err != nil {
				log.Printf("warning: failed to decrypt contact %s (cards=%d): %v", contact.ID, len(contact.Cards), err)
				failedContacts++
				continue // Skip this contact instead of failing entirely
			}
			aos = append(aos, *ao)
		}

		if len(aos)+failedContacts >= total || len(contacts) == 0 {
			break
		}
		page++
		
		// Additional safety check - if we've hit the max page limit, log a warning
		if page >= maxPages {
			log.Printf("warning: Hit maximum page limit (%d), stopping contact export", maxPages)
			break
		}
	}

	log.Printf("debug: Successfully processed %d contacts, failed to decrypt %d contacts", len(aos), failedContacts)
	
	// Check for critical failure scenario - all contacts failed to decrypt
	if total > 0 && failedContacts == total {
		log.Printf("CRITICAL: All %d contacts failed to decrypt. Check PGP keys and password.", total)
	}
	
	return aos, nil
}

func (b *backend) QueryAddressObjects(ctx context.Context, path string, query *carddav.AddressBookQuery) ([]carddav.AddressObject, error) {
	log.Printf("debug: QueryAddressObjects called for path: %s", path)
	
	req := carddav.AddressDataRequest{AllProp: true}
	if query != nil {
		req = query.DataRequest
		log.Printf("debug: Query has %d PropFilters, FilterTest=%s", len(query.PropFilters), query.FilterTest)
	}

	log.Printf("debug: About to call ListAddressObjects with path: %s", addressBook.Path)
	// TODO: optimize
	all, err := b.ListAddressObjects(ctx, addressBook.Path, &req)
	if err != nil {
		log.Printf("error: QueryAddressObjects failed to list objects: %v", err)
		return nil, err
	}

	log.Printf("debug: QueryAddressObjects got %d objects", len(all))
	
	// If query is nil or has no filters, return all contacts
	// This fixes the issue where empty filter queries would return no contacts
	if query == nil || len(query.PropFilters) == 0 {
		log.Printf("debug: No filters specified, returning all %d objects", len(all))
		return all, nil
	}
	
	log.Printf("debug: Applying filter with %d PropFilters", len(query.PropFilters))
	filtered, err := carddav.Filter(query, all)
	if err != nil {
		log.Printf("error: QueryAddressObjects filter failed: %v", err)
		return nil, err
	}
	
	log.Printf("debug: QueryAddressObjects returning %d filtered objects", len(filtered))
	return filtered, nil
}

func (b *backend) PutAddressObject(ctx context.Context, path string, card vcard.Card, opts *carddav.PutAddressObjectOptions) (ao *carddav.AddressObject, err error) {
	log.Printf("debug: PutAddressObject called for path: %s", path)
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return nil, err
	}

	// Log the incoming vCard data
	log.Printf("debug: Processing vCard with %d fields", len(card))
	for k, fields := range card {
		log.Printf("debug: vCard field %s: %d values", k, len(fields))
	}

	if b.mainAccountKey == nil {
		return nil, errors.New("no main account key available for contact encryption")
	}
	
	contactImport, err := formatCard(card, b.mainAccountKey)
	if err != nil {
		return nil, err
	}

	var contact *protonmail.Contact

	var req carddav.AddressDataRequest
	if _, getErr := b.GetAddressObject(ctx, path, &req); getErr == nil {
		contact, err = b.c.UpdateContact(id, contactImport)
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("debug: Creating new contact with mainAccountKey keyid=%X", b.mainAccountKey.PrimaryKey.KeyId)
		resps, err := b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
		if err != nil {
			log.Printf("error: CreateContacts API call failed: %v", err)
			return nil, err
		}
		log.Printf("debug: CreateContacts returned %d responses", len(resps))
		if len(resps) != 1 {
			return nil, errors.New("hydroxide/carddav: expected exactly one response when creating contact")
		}
		resp := resps[0]
		log.Printf("debug: Contact creation response: Code=%d, Contact=%v", resp.Response.Code, resp.Response.Contact != nil)
		if err := resp.Err(); err != nil {
			log.Printf("error: Contact creation failed with response error: %v (Code: %d)", err, resp.Response.Code)
			return nil, err
		}
		contact = resp.Response.Contact
		log.Printf("debug: Successfully created contact with ID: %s", contact.ID)
	}
	contact.Cards = contactImport.Cards // Not returned by the server

	// TODO: increment b.total if necessary
	b.putCache(contact)

	return &carddav.AddressObject{
		Path:    formatAddressObjectPath(contact.ID),
		ModTime: contact.ModifyTime.Time(),
		// TODO: stronger ETag
		ETag: fmt.Sprintf("%x%x", contact.ModifyTime, contact.Size),
		Card: card,
	}, nil
}

func (b *backend) DeleteAddressObject(ctx context.Context, path string) error {
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return err
	}
	resps, err := b.c.DeleteContacts([]string{id})
	if err != nil {
		return err
	}
	if len(resps) != 1 {
		return errors.New("hydroxide/carddav: expected exactly one response when deleting contact")
	}
	resp := resps[0]
	// TODO: decrement b.total if necessary
	b.deleteCache(id)
	return resp.Err()
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		b.locker.Lock()
		if event.Refresh&protonmail.EventRefreshContacts != 0 {
			b.cache = make(map[string]*protonmail.Contact)
			b.total = -1
		} else if len(event.Contacts) > 0 {
			for _, eventContact := range event.Contacts {
				switch eventContact.Action {
				case protonmail.EventCreate:
					if b.total >= 0 {
						b.total++
					}
					fallthrough
				case protonmail.EventUpdate:
					b.cache[eventContact.ID] = eventContact.Contact
				case protonmail.EventDelete:
					delete(b.cache, eventContact.ID)
					if b.total >= 0 {
						b.total--
					}
				}
			}
		}
		b.locker.Unlock()
	}
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, primaryKeyID uint64, events <-chan *protonmail.Event) http.Handler {
	log.Printf("debug: NewHandler called with %d private keys", len(privateKeys))
	
	if len(privateKeys) == 0 {
		panic("hydroxide/carddav: no private key available")
	}

	// Find the main account key using the primaryKeyID from authentication
	var mainAccountKey *openpgp.Entity
	
	// Log details about each key and find the main account key
	for i, entity := range privateKeys {
		log.Printf("debug: CardDAV key %d: algorithm=%s (code=%d), keyid=%X", 
			i, entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.KeyId)
		
		// Look for the key that matches the primary key ID from authentication
		if entity.PrimaryKey.KeyId == primaryKeyID {
			mainAccountKey = entity
			log.Printf("debug: Found primary account key: algorithm=%s, keyid=%X, index=%d", 
				entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.KeyId, i)
			break
		}
	}
	
	// Fallback to first key if primary key ID not found
	if mainAccountKey == nil {
		mainAccountKey = privateKeys[0]
		log.Printf("debug: Primary key ID %X not found, using first key as fallback: algorithm=%s, keyid=%X", 
			primaryKeyID, mainAccountKey.PrimaryKey.PubKeyAlgo, mainAccountKey.PrimaryKey.KeyId)
	}
	
	log.Printf("debug: CardDAV will use main account key: algorithm=%s (code=%d), keyid=%X for contact encryption", 
		mainAccountKey.PrimaryKey.PubKeyAlgo, mainAccountKey.PrimaryKey.PubKeyAlgo, mainAccountKey.PrimaryKey.KeyId)

	// Create optimized keyring with only the main account key for CardDAV operations
	cardDAVKeyring := openpgp.EntityList{mainAccountKey}
	log.Printf("debug: CardDAV optimized keyring created with 1 key (reduced from %d keys)", len(privateKeys))

	b := &backend{
		c:              c,
		cache:          make(map[string]*protonmail.Contact),
		total:          -1,
		privateKeys:    privateKeys,
		mainAccountKey: mainAccountKey,
		cardDAVKeyring: cardDAVKeyring,
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &carddav.Handler{Backend: b}
}
