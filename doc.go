/*
Package styx serves network filesystems using the 9P2000 protocol.

The styx package provides types and routines for implementing 9P
servers. The files served may reflect real files on the host operating
system, or an in-memory filesystem, or bi-directional RPC endpoints.
Regardless, the protocol operations used to access these files are
the same.

The ListenAndServe and ListenAndServeTLS functions run 9P servers bound
to a TCP port. To create a 9P server, define a type that implements the
Serve9P method.  The HandlerFunc type allows regular functions to be used:

	fs := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			switch msg := s.Request().(type) {
			case styx.Twalk:
				msg.Rwalk(os.Stat(msg.Path()))
			case styx.Topen:
				msg.Ropen(os.OpenFile(msg.Path(), msg.Flag, 0777))
			case styx.Tstat:
				msg.Rstat(os.Stat(msg.Path())
			}
		}
	})
	styx.ListenAndServe(":564", fs)

Multiple handlers can be overlaid using the Stack function.

	echo := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			log.Printf("%s %q %s", s.User, s.Access, s.Request())
		}
		log.Printf("session %s %q ended", s.User, s.Access)
	})
	styx.ListenAndServe(":564", styx.Stack(echo, handler))

Handlers may pass data downstream using a message's WithContext
method:

	sessionid := styx.HandlerFunc(func(s *styx.Session) {
		uuid := rand.Int63()
		for s.Next() {
			msg := s.Request()
			ctx := context.WithValue(msg.Context(), "session", uuid)
			s.UpdateRequest(msg.WithContext(ctx))
		}
	})
	styx.ListenAndServe(":564", styx.Stack(sessionid, echo, fs))

*/
package styx
