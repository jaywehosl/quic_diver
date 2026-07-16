//go:build windows

package sysdns

import "testing"

// Проверяем на живой машине: адаптеры находятся и у каждого есть ключи ОБОИХ
// семейств. Если ключа v6 нет — подмена v6-DNS молча не сработает, и резолв
// утечёт провайдеру мимо туннеля.
//
// Реестр судить об активности не позволяет: у v6-ключей адреса нет вообще (он
// приходит из RA), поэтому и спрашиваем ОС.
func TestLiveAdaptersHaveBothFamilies(t *testing.T) {
	live, err := liveAdapters()
	if err != nil {
		t.Skipf("нет поднятых адаптеров (машина без сети?): %v", err)
	}
	t.Logf("поднятых адаптеров: %d", len(live))
	for _, guid := range live {
		for _, key := range []string{v4Ifaces, v6Ifaces} {
			k, err := openKey(key, guid)
			if err != nil {
				t.Errorf("%s: нет ключа %s: %v", guid, key, err)
				continue
			}
			k.Close()
		}
	}
}
