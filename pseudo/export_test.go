package pseudo

import "net/netip"

// MarkerRanges hands the two ranges of the address pseudonyms to the
// external tests, which hold the detectors to them.
var MarkerRanges = []netip.Prefix{cgnatPrefix, ulaPseudoPrefix}
