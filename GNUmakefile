
.PHONY: .default dist .dist .update
.default: release
dist: release .dist

include Makefile.win


OS_UNAME:=$(patsubst CYGWIN_NT%,CYGWIN_NT,$(shell uname))
ifneq ($(OS_UNAME),)
OS:=$(OS_UNAME)
endif

ifeq ($(OS),Windows_NT)
.dist .update:
	c:/cygwin/bin/bash -c 'PATH="/bin:$$PATH" /bin/make $@'
else
EL_CVS_BASE:=el-cvs-$(shell date +%Y-%m-%d-%H%M)
.dist:
	cp el.exe $(EL_CVS_BASE).exe
	zip -m $(EL_CVS_BASE).zip $(EL_CVS_BASE).exe
	scp $(EL_CVS_BASE).zip gotti-ftp@gotti.dnsalias.org:httpdocs/el
.update:
	git pull
endif

OPTIONS_VLC = WINDOWS;ELC$(foreach FEATURE,$(FEATURES),;$(FEATURE))

vlc_options: make.conf
	echo "$(OPTIONS_VLC)" >vlc_options
