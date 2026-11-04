# SPDX-License-Identifier: MIT
# FreeBSD base make; standalone pilot only. No install target or root-build wiring.
.MAIN: all
.if ${MACHINE_ARCH} != "amd64"
.error This diagnostic pilot currently targets FreeBSD amd64
.endif
SOURCE_DIR:= ${.PARSEDIR:tA}
BUILD_DIR?= ${.OBJDIR}/diagnostic-build
CXX?= c++
CXXFLAGS?= -O2 -g
PILOT_FLAGS= -std=c++17 -Wall -Wextra -Werror -pthread
SOURCES= ${SOURCE_DIR}/main.cpp ${SOURCE_DIR}/../native_capture.cpp \
    ${SOURCE_DIR}/../native_program.cpp ${SOURCE_DIR}/../native_event_decoder.cpp \
    ${SOURCE_DIR}/../dtrace_session.cpp
HEADERS= ${SOURCE_DIR}/support.h ${SOURCE_DIR}/target_watch.h ${SOURCE_DIR}/../native_capture.h \
    ${SOURCE_DIR}/../native_program.h ${SOURCE_DIR}/../native_event_decoder.h \
    ${SOURCE_DIR}/../dtrace_session.h
BINARY= ${BUILD_DIR}/procmon-freebsd-capture
.PHONY: all
all: ${BINARY}
${BINARY}: ${SOURCES} ${HEADERS}
	mkdir -p ${BUILD_DIR:Q}
	${CXX} ${CPPFLAGS} ${CXXFLAGS} ${PILOT_FLAGS} ${SOURCES} ${LDFLAGS} -ldtrace -o ${BINARY:Q}
