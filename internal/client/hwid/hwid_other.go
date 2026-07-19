//go:build !windows

package hwid

import "os"

// machineID — системный идентификатор машины.
//
// /etc/machine-id заводится при установке системы и переживает переустановку
// приложений (ровно то, что нужно учёту). Путь в /var/lib/dbus — старое место
// того же значения, встречается на части дистрибутивов.
//
// На Android этих файлов нет и они недоступны без прав — там отпечаток даст
// платформенный слой (ANDROID_ID и свойства сборки), когда появится клиент.
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := normalize(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}
