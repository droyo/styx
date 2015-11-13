// Package styxproto provides low-level routines for parsing
// and producing 9P2000 messages.
//
// The styxproto package is to be used for making higher-level
// 9P2000 libraries. The parsing routines within make very few
// assumptions or decisions, so that it may be used for a wide
// variety of higher-level packages. When decoding messages, memory usage is bounded
// using a fixed-size buffer. This allows servers using the styxproto
// package to have predictable resource usage based on the number of connections.
//
// To minimize allocations, the styxproto package does not decode
// messages. Instead, messages are validated and wrapped with convenient
// accessor methods.
package styxproto
