// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"testing"
)

func TestCSBRejectsSeccompControlFDInjection(t *testing.T) {
	src := csbSource(t, "ioctl$SECCOMP_IOCTL_NOTIF_ADDFD(0x0, 0x40182103, "+
		"&(0x7f0000000000)={0x0, 0x1, 0x3, 0x1, 0x0})\n", false)
	requireCSource(t, src, "csb_seccomp_addfd_0 + 16) <= 2")
}
