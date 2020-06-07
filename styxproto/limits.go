package styxproto

const maxInt = int(^uint(0) >> 1)

// Validating messages becomes more complicated if we allow arbitrarily-long
// values for some of the non-fixed fields in a message.  To simplify
// things, we set some limits on how big any of these fields can be.

// Minimum size of a message
var minSizeLUT = [...]int{
	msgTversion: 13,             // size[4] Tversion tag[2] msize[4] version[s]
	msgRversion: 13,             // size[4] Rversion tag[2] mversion[s]
	msgTauth:    15,             // size[4] Tauth tag[2] afid[4] uname[s] aname[s]
	msgRauth:    20,             // size[4] Rauth tag[2] aqid[13]
	msgTattach:  19,             // size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
	msgRattach:  20,             // size[4] Rattach tag[2] qid[13]
	msgRerror:   9,              // size[4] Rerror tag[2] ename[s]
	msgTflush:   9,              // size[4] Tflush tag[2] oldtag[2]
	msgRflush:   7,              // size[4] Rflush tag[2]
	msgTwalk:    17,             // size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
	msgRwalk:    9,              // size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
	msgTopen:    12,             // size[4] Topen tag[2] fid[4] mode[1]
	msgRopen:    24,             // size[4] Ropen tag[2] qid[13] iounit[4]
	msgTcreate:  18,             // size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
	msgRcreate:  24,             // size[4] Rcreate tag[2] qid[13] iounit[4]
	msgTread:    IOHeaderSize,   // size[4] Tread tag[2] fid[4] offset[8] count[4]
	msgRread:    11,             // size[4] Rread tag[2] count[4] data[count]
	msgTwrite:   IOHeaderSize,   // size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
	msgRwrite:   11,             // size[4] Rwrite tag[2] count[4]
	msgTclunk:   11,             // size[4] Tclunk tag[2] fid[4]
	msgRclunk:   7,              // size[4] Rclunk tag[2]
	msgTremove:  11,             // size[4] Tremove tag[2] fid[4]
	msgRremove:  7,              // size[4] Rremove tag[2]
	msgTstat:    11,             // size[4] Tstat tag[2] fid[4]
	msgRstat:    9 + minStatLen, // size[4] Rstat tag[2] stat[n]
	msgTwstat:   11,             // size[4] Twstat tag[2] fid[4] stat[n]
	msgRwstat:   7,              // size[4] Rwstat tag[2]
}

// Maximum size of a message
var maxSizeLUT = [...]int{
	msgTversion: minSizeLUT[msgTversion] + MaxVersionLen,
	msgRversion: minSizeLUT[msgRversion] + MaxVersionLen,
	msgTauth:    minSizeLUT[msgTauth] + MaxUidLen + MaxAttachLen,
	msgRauth:    minSizeLUT[msgRauth],
	msgTattach:  minSizeLUT[msgTattach] + MaxUidLen + MaxAttachLen,
	msgRattach:  minSizeLUT[msgRattach],
	msgRerror:   minSizeLUT[msgRerror],
	msgTflush:   minSizeLUT[msgTflush],
	msgRflush:   minSizeLUT[msgRflush],
	msgTwalk:    minSizeLUT[msgTwalk] + (MaxFilenameLen+2)*MaxWElem,
	msgRwalk:    minSizeLUT[msgRwalk] + (13 * MaxWElem),
	msgTopen:    minSizeLUT[msgTopen],
	msgRopen:    minSizeLUT[msgRopen],
	msgTcreate:  minSizeLUT[msgTcreate] + MaxFilenameLen,
	msgRcreate:  minSizeLUT[msgRcreate],
	msgTread:    minSizeLUT[msgTread],
	msgRread:    1<<32 - 1,
	msgTwrite:   1<<32 - 1,
	msgRwrite:   minSizeLUT[msgRwrite],
	msgTclunk:   minSizeLUT[msgTclunk],
	msgRclunk:   minSizeLUT[msgRclunk],
	msgTremove:  minSizeLUT[msgTremove],
	msgRremove:  minSizeLUT[msgRremove],
	msgTstat:    minSizeLUT[msgTstat],
	msgRstat:    minSizeLUT[msgRstat] + MaxFilenameLen + (MaxUidLen * 3),
	msgTwstat:   minSizeLUT[msgTwstat] + MaxFilenameLen + (MaxUidLen * 3),
	msgRwstat:   minSizeLUT[msgRwstat],
}

// IOHeaderSize is the length of all fixed-width fields in a Twrite or Tread
// message. Twrite and Tread messages are defined as
//
// 	size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
// 	size[4] Tread  tag[2] fid[4] offset[8] count[4]
//
const IOHeaderSize = 4 + 1 + 2 + 4 + 8 + 4

// MaxVersionLen is the maximum length of the protocol version string in bytes
const MaxVersionLen = 20

// MaxFileLen is the maximum length of a single file. While the 9P protocol
// supports files with a length of up to 8 EB (exabytes), to reduce the risk of
// overflow errors, the styxproto package only supports lengths of up to 4 EB
// so that it may fit within a signed 64-bit integer.
const MaxFileLen = 1<<63 - 1

// MaxOffset is the maximum value of the offset field in Tread and Twrite requests
const MaxOffset = 1<<63 - 1

// MaxFilenameLen is the maximum length of a file name in bytes
const MaxFilenameLen = 255

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

// MinBufSize is the minimum size (in bytes) of the internal buffers in a Decoder.
const MinBufSize = MaxWElem*(MaxFilenameLen+2) + 13 + 4

// DefaultBufSize is the default buffer size used in a Decoder
const DefaultBufSize = 8192

const megabyte = 1 << 20

// DefaultMaxSize is the default maximum size of a 9P message.
const DefaultMaxSize = 8 * megabyte

// See stat(5) or stat(9P) for details on stat structure
const statFixedSize = 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8

const minStatLen = statFixedSize + (4 * 2) // name[s], uid[s], gid[s], muid[s]

// MaxStatLen is the maximum size of a Stat structure.
const MaxStatLen = minStatLen + MaxFilenameLen + (MaxUidLen * 3)

const maxWalkLen = MaxWElem * MaxFilenameLen

// largest possible message
const maxMsgSize = 1<<32 - 1

// Smallest possible message (Rclunk, Rwstat etc)
const minMsgSize = 4 + 1 + 2
