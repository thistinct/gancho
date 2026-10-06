//! Access to the Uruguayan cédula de identidad electrónica.
//!
//! The card is a Gemalto/Thales IAS-ECC applet holding one RSA-2048 signing
//! key (protected by the user PIN) and its certificate issued by
//! "AC Ministerio del Interior". Two backends reach it:
//!
//! - [`native`]: talks to the card directly over the operating system's PC/SC
//!   service. Needs no vendor middleware; this is the default.
//! - [`pkcs11`]: goes through an installed PKCS#11 module.

pub mod native;
pub mod pkcs11;
