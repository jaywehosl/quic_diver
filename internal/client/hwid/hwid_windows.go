//go:build windows

package hwid

import (
	"golang.org/x/sys/windows/registry"
)

// machineID — MachineGuid из реестра.
//
// Почему именно он: заводится при установке Windows и живёт до её переустановки.
// Значит переустановка клиента отпечаток не меняет (учёт устройств не слетает
// после обновления), а вот другая машина или свежая ОС дадут другой.
//
// Ключ общий для всей машины (HKLM), а не пользовательский — иначе вход под
// вторым пользователем выглядел бы новым устройством и обходил лимит.
func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return normalize(guid)
}
