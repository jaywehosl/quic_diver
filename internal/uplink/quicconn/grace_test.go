package quicconn_test

import (
	"context"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"quicdiver/internal/uplink/quicconn"
)

// Закрывать транспорт покинутого пути НЕЛЬЗЯ — даже после Path.Close().
//
// Transport.Close() делает destroy всем соединениям своего транспорта, а сессия
// остаётся в его handlers и после переезда; отвязать её quic-go v0.60 не даёт.
// Тест фиксирует это ограничение upstream: если оно когда-нибудь исчезнет, тест
// упадёт — и тогда сокеты покинутых путей можно будет освобождать полностью.
func TestClosingRetiredTransportKillsSession(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	pcA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	trA := &quic.Transport{Conn: pcA}
	defer trA.Close()

	qc, err := trA.Dial(ctx, ln.Addr().(*net.UDPAddr), clientTLS,
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer qc.CloseWithError(0, "")

	echo(t, ctx, qc, "путь A")

	trB, pathB := addPath(t, ctx, qc) // A → B
	echo(t, ctx, qc, "путь B")        // по пути идёт трафик — как в бою

	trC, _ := addPath(t, ctx, qc) // B → C, теперь B покинут
	defer trC.Close()
	echo(t, ctx, qc, "путь C")

	if err := pathB.Close(); err != nil {
		t.Fatalf("Path.Close на покинутом пути: %v", err)
	}
	_ = trB.Close()

	// осторожно с shadowing: проверяем именно ошибку обмена, а не err от Dial
	sendErr := qc.SendDatagram([]byte("после закрытия B"))
	if sendErr == nil {
		rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
		_, sendErr = qc.ReceiveDatagram(rctx)
		rcancel()
	}
	if sendErr == nil {
		t.Fatal("сессия пережила закрытие покинутого транспорта — ограничение upstream снято, " +
			"пора освобождать сокеты покинутых путей в Conn.retire")
	}
	t.Logf("сессия умерла, как и ожидалось: %v", sendErr)
}

// Активный путь закрывать нельзя — библиотека обязана отказать. Если это начнёт
// молча проходить, retire оборвёт живой путь.
func TestClosingActivePathRefused(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()

	qc, err := tr.Dial(ctx, ln.Addr().(*net.UDPAddr), clientTLS,
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer qc.CloseWithError(0, "")

	trNew, path := addPath(t, ctx, qc) // этот путь стал активным
	defer trNew.Close()

	if err := path.Close(); err == nil {
		t.Fatal("закрытие АКТИВНОГО пути прошло без ошибки — retire мог бы оборвать живой путь")
	} else {
		t.Logf("активный путь закрыть отказано, как и должно: %v", err)
	}
}

// Разоружение покинутого пути (Path.Close + урезание буферов) сессию не трогает:
// именно на этом держится Conn.retire — память возвращаем, связь не рвём.
func TestRetireKeepsSessionAlive(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	ln := startEcho(t, serverTLS)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	uc := dial(t, ctx, ln.Addr().String(), clientTLS)
	defer uc.Close()
	c := uc.(*quicconn.Conn)

	// два переезда подряд: после второго первый путь разоружается со своим Path
	for i, name := range []string{"первый переезд", "второй переезд"} {
		mctx, mcancel := context.WithTimeout(ctx, 8*time.Second)
		err := c.Migrate(mctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		mcancel()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		echo(t, ctx, c.QUIC(), name)
		t.Logf("%s (#%d): сессия жива после разоружения предыдущего пути", name, i+1)
	}
}

// addPath открывает новый сокет, валидирует путь и переключается на него.
func addPath(t *testing.T, ctx context.Context, qc *quic.Conn) (*quic.Transport, *quic.Path) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	path, err := qc.AddPath(tr)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := path.Probe(pctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if err := path.Switch(); err != nil {
		t.Fatalf("Switch: %v", err)
	}
	return tr, path
}

// echo гоняет датаграмму туда-обратно — так видно, что сессия действительно жива.
func echo(t *testing.T, ctx context.Context, qc *quic.Conn, what string) {
	t.Helper()
	if err := qc.SendDatagram([]byte(what)); err != nil {
		t.Fatalf("%s: SendDatagram: %v", what, err)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got, err := qc.ReceiveDatagram(rctx)
	if err != nil {
		t.Fatalf("%s: сессия мертва: %v", what, err)
	}
	if string(got) != what {
		t.Fatalf("%s: пришло %q", what, got)
	}
}
