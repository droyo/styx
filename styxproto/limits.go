package styxproto

// Validating messages becomes more complicated if we allow arbitrarily-long
// values for some of the non-fixed fields in a message.  To simplify
// things, we set some limits on how big any of these fields can be.

// MaxVersionLen is the maximum length of the protocol version string in bytes
const MaxVersionLen = 20

// MaxOffset is the maximum value of the offset field in Tread and Twrite requests
const MaxOffset = 1<<63 - 1

// MaxFilenameLen is the maximum length of a file name in bytes
const MaxFilenameLen = 512

// MaxWElem is the maximum allowed number of path elements in a Twalk
// request
const MaxWElem = 16

// MaxUidLen is the maximum length (in bytes) of a username or
// group identifier.
const MaxUidLen = 45

// MaxErrorLen is the maximum length (in bytes) of the Ename field
// in an Rerror message.
const MaxErrorLen = 512

// MaxAttachLen is the maximum length (in bytes) of the aname field
// of Tattach and Tauth requests.
const MaxAttachLen = 255

// MinBufSize is the minimum size (in bytes) of the internal buffers in a Parser.
const MinBufSize = MaxWElem*(MaxFilenameLen+2) + 12

// DefaultBufSize is the default buffer size used in a Parser
const DefaultBufSize = 1 << 20

// See stat(5) for layout of a stat structure
const minStatLen = 49
const maxStatLen = minStatLen + MaxFilenameLen + (MaxUidLen * 3)

const maxWalkLen = MaxWElem * MaxFilenameLen

// largest possible message
const maxMsgSize = 1<<32 - 1

// Smallest possible message (Rclunk, Rwstat etc)
const minMsgSize = 4 + 1 + 2

// Minimum size of a message, not counting size[4].
var minSizeLUT = [...]int8{
	msgTversion: 9,              // Tversion tag[2] msize[4] version[s]
	msgRversion: 9,              // Rversion tag[2] mversion[s]
	msgTauth:    11,             // Tauth tag[2] afid[4] uname[s] aname[s]
	msgRauth:    16,             // Rauth tag[2] aqid[13]
	msgTattach:  15,             // Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
	msgRattach:  16,             // Rattach tag[2] qid[13]
	msgRerror:   5,              // Rerror tag[2] ename[s]
	msgTflush:   5,              // Tflush tag[2] oldtag[2]
	msgRflush:   3,              // Rflush tag[2]
	msgTwalk:    13,             // Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
	msgRwalk:    5,              // Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
	msgTopen:    8,              // Topen tag[2] fid[4] mode[1]
	msgRopen:    20,             // Ropen tag[2] qid[13] iounit[4]
	msgTcreate:  14,             // Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
	msgRcreate:  20,             // Rcreate tag[2] qid[13] iounit[4]
	msgTread:    19,             // Tread tag[2] fid[4] offset[8] count[4]
	msgRread:    7,              // Rread tag[2] count[4] data[count]
	msgTwrite:   19,             // Twrite tag[2] fid[4] offset[8] count[4] data[count]
	msgRwrite:   7,              // Rwrite tag[2] count[4]
	msgTclunk:   7,              // Tclunk tag[2] fid[4]
	msgRclunk:   3,              // Rclunk tag[2]
	msgTremove:  7,              // Tremove tag[2] fid[4]
	msgRremove:  3,              // Rremove tag[2]
	msgTstat:    7,              // Tstat tag[2] fid[4]
	msgRstat:    5 + minStatLen, // Rstat tag[2] stat[n]
	msgTwstat:   9,              // Twstat tag[2] fid[4] stat[n]
	msgRwstat:   3,              // Rwstat tag[2]
}
