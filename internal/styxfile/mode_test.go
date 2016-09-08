package styxfile

import (
	"os"
	"testing"

	"aqwari.net/net/styx/styxproto"
)

func TestFileMode(t *testing.T) {
	var perm uint32 = styxproto.DMDIR |
		styxproto.DMEXCL |
		styxproto.DMTMP |
		0750
	mode := ModeOS(perm)
	if mode&os.ModeDir == 0 {
		t.Error("DMDIR")
	}
	if mode&os.ModeExclusive == 0 {
		t.Error("DMEXCL")
	}
	if mode&os.ModeTemporary == 0 {
		t.Error("DMTMP")
	}
	if mode&os.ModePerm != 0750 {
		t.Errorf("perm %o != %o", mode&os.ModePerm, perm&0777)
	}
}

func TestPerm(t *testing.T) {
	var mode os.FileMode = os.ModeDir |
		os.ModeExclusive |
		os.ModeTemporary |
		0750
	perm := Mode9P(mode)
	if perm&styxproto.DMDIR == 0 {
		t.Error("ModeDir")
	}
	if perm&styxproto.DMEXCL == 0 {
		t.Error("ModeExclusive")
	}
	if perm&styxproto.DMTMP == 0 {
		t.Error("ModeTemporary")
	}
	if perm&0777 != 0750 {
		t.Error("ModePerm")
	}
}
