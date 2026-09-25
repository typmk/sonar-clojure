(ns net.typemark.sonar.hooks
  "Rules detected by clj-kondo hooks rather than by this plugin.

  Their detection lives in net.typemark.sonar.security, exported under
  resources/clj-kondo.exports/ for a project to import into .clj-kondo/.
  Keyed on the RESOLVED var, they do not
  confuse a local named `query` with next.jdbc/execute!, which is where every
  false positive the audits measured came from.

  The keys stay registered here because the Sonar side must have a rule for a
  finding to attach to. Detection moved; registration did not.")

