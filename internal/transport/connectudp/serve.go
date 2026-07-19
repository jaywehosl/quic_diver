package connectudp

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
)

// IsRequest — это запрос CONNECT-UDP (RFC 9298)?
//
// Отличаем по расширенному CONNECT с нашим :protocol. Обычный CONNECT (TCP-флоу
// гибрида) и Extended CONNECT connect-ip идут другими путями, поэтому проверка
// должна быть точной, а не «метод CONNECT».
func IsRequest(r *http.Request) bool {
	return r.Method == http.MethodConnect && r.Proto == Protocol
}

// Target — целевой адрес из пути запроса.
func Target(r *http.Request) (netip.AddrPort, error) {
	return ParsePath(r.URL.Path)
}

// Accept принимает CONNECT-UDP: отвечает согласием и отдаёт флоу как net.Conn.
//
// Вызывающий сам решает, куда его склеить — наружу через свой сокет или транзитом
// на следующий узел. Здесь только транспорт, без политики маршрутизации.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return nil, errNoStream
	}
	dst, err := Target(r)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return nil, err
	}
	// Согласие (RFC 9298 §3): 2xx до первой датаграммы. Заголовки отправляем
	// ДО перехвата стрима — после него запись пойдёт мимо HTTP-слоя.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	str := streamer.HTTPStream()
	return &flowConn{
		str:    str,
		closer: str.Close,
		ctx:    context.Background(),
		cancel: func() {},
		remote: net.UDPAddrFromAddrPort(dst),
	}, nil
}

type noStreamError struct{}

func (noStreamError) Error() string {
	return "connectudp: HTTP-слой не отдаёт стрим (нужен http3)"
}

var errNoStream = noStreamError{}
