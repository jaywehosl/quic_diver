package dns

import (
	"encoding/base64"
	"io"
	"net/http"
)

// MaxMessageSize — предел размера DNS-сообщения (RFC 8484 §6).
const MaxMessageSize = 65535

// Handler — DoH-эндпоинт узла (RFC 8484). Вешается на тот же HTTP/3-сервер, что
// и connect-ip, поэтому DNS клиента едет в том же QUIC-соединении: отдельного
// канала нет, утечь резолву некуда.
func Handler(r *Resolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		query, err := readQuery(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := r.Query(req.Context(), query)
		if err != nil {
			http.Error(w, "resolve failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "no-store") // TTL живёт в самом ответе
		_, _ = w.Write(resp)
	})
}

// readQuery достаёт DNS-сообщение из POST-тела или из ?dns= (base64url) в GET.
func readQuery(req *http.Request) ([]byte, error) {
	switch req.Method {
	case http.MethodPost:
		return io.ReadAll(io.LimitReader(req.Body, MaxMessageSize))
	case http.MethodGet:
		return base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
	default:
		return nil, errMethod{}
	}
}

type errMethod struct{}

func (errMethod) Error() string { return "поддерживаются только GET и POST" }
