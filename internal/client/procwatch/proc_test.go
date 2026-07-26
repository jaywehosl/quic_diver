package procwatch

import "testing"

func TestListUserProcesses(t *testing.T) {
	procs, err := ListUserProcesses()
	if err != nil {
		t.Fatalf("ListUserProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("список процессов пуст")
	}
	t.Logf("Получено %d процессов", len(procs))
}
