package styx

type Type uint8
type Qid [13]uint8

func (q Qid) Type() Type {
	return Type(q[0])
}

func (q Qid) Version() uint32 {
	return uint32(q[1] | q[2] << 8 | q[3] << 16 | q[4] << 24)
}

func (q Qid) Path() uint32 {
	return uint32(q[5] | q[6] << 8 | q[7] << 16 | q[8] << 32 | q[9] << 64 | q[10] << 128 | q[11] << 256 | q[12] << 512)
}

const (
	tversion uint8 = 100 + iota
	rversion
	tauth
	rauth
	tattach
	rattach
	terror
	rerror
	tflush
	rflush
	twalk
	rwalk
	topen
	ropen
	tcreate
	rcreate
	tread
	rread
	twrite
	rwrite
	tclunk
	rclunk
	tremove
	rremove
	tstat
	rstat
	twstat
	rwstat
	tmax

	topenfd = 98
	ropenfd = 99
)
