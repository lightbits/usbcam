// vdb - Version 3
// Changelog
// (3) Float and int sliders and checkboxes
// (2) Message passing from browser to vdb
// (1) Works on unix and windows

#ifndef VDB_HEADER_INCLUDE
#define VDB_HEADER_INCLUDE

// STREAM MODE - Run a block of code without blocking the caller.
// EXAMPLE -
//     if (vdb_begin()) {
//         vdb_point()
//         vdb_end();
//     }
int  vdb_begin(); // Returns true if vdb is not already busy sending data
void vdb_end();

// LOOP MODE - Run a block of code at a specified framerate until
// we receive a 'continue' signal from the client.
// EXAMPLE -
//     while (vdb_loop(60)) {
//         static float t = 0.0f; t += 1.0f/60.0f;
//         vdb_point(cosf(t), sinf(t));
//     }
int vdb_loop(int fps);

// These functions assign a RGB color to all subsequent draw calls
// The ramp functions will map the input to a smooth gradient, while
// the primary functions (red/green/blue/...) will color the element
// a specified shade of the given primary color.
void vdb_color_rampf(float value);
void vdb_color_ramp(int i);
void vdb_color_red(int shade);
void vdb_color_green(int shade);
void vdb_color_blue(int shade);
void vdb_color_black(int shade);
void vdb_color_white(int shade);

// These functions make the next elements semi- or fully opaque,
// with an opacity that can be adjusted in the browser.
void vdb_translucent();
void vdb_opaque();

// These functions maps your input coordinates from the specified
// range to the corresponding edges of the viewport.
void vdb_xrange(float left, float right);
void vdb_yrange(float bottom, float top);
void vdb_zrange(float z_near, float z_far);

// These are your basic 2D draw commands
void vdb_point(float x, float y);
void vdb_line(float x1, float y1, float x2, float y2);
void vdb_fillRect(float x, float y, float w, float h);
void vdb_circle(float x, float y, float r);

// This will send a densely packed array of (w x h x 3) bytes and
// render it as an image of RGB values, each one byte.
void vdb_imageRGB8(const void *data, int w, int h);

// These functions let you modify variables in a vdb_begin or vdb_loop block.
// You can build a simple graphical user interface with sliders and checkboxes.
void vdb_slider1f(const char *in_label, float *x, float min_value, float max_value);
void vdb_slider1i(const char *in_label, int *x, int min_value, int max_value);
void vdb_checkbox(const char *in_label, int *x);

// You probably don't want to mess with this, but if you do,
// this pushes data to the buffer that is sent on each vdb_end.
// You can use this in conjunction with your own parser at the
// browser-side to implement custom rendering. See app.js for
// an example parser, and the any of the vdb_point/line/...
// for an example render command.
void *vdb_push_bytes(const void *data, int count);

#endif // VDB_HEADER_INCLUDE

#define VDB_RELEASE

#define vdb_assert(EXPR)  { if (!(EXPR)) { printf("[error]\n\tAssert failed at line %d in file %s:\n\t'%s'\n", __LINE__, __FILE__, #EXPR); return 0; } }
#ifdef VDB_LOG_DEBUG
#define vdb_log(...)      { printf("[vdb] %s@L%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); }
#else
#define vdb_log(...)      { }
#endif
#define vdb_log_once(...) { static int first = 1; if (first) { printf("[vdb] "); printf(__VA_ARGS__); first = 0; } }
#define vdb_err_once(...) { static int first = 1; if (first) { printf("[vdb] Error at line %d in file %s:\n[vdb] ", __LINE__, __FILE__); printf(__VA_ARGS__); first = 0; } }
#define vdb_critical(EXPR) if (!(EXPR)) { printf("[vdb] Something went wrong at line %d in file %s\n", __LINE__, __FILE__); vdb_shared->critical_error = 1; return 0; }

#if defined(_WIN32) || defined(_WIN64)
#define VDB_WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#define VDB_UNIX
#include <sys/mman.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Draw commands are stored in a work buffer that is allocated
// once on the first vdb_begin call, and stays a fixed size that
// is given below in number-of-bytes. If you are memory constrained,
// or if you need more memory than allocated by default, you can
// define your own work buffer size before #including vdb.
#ifndef VDB_WORK_BUFFER_SIZE
#define VDB_WORK_BUFFER_SIZE (32*1024*1024)
#endif

// Messages received from the browser are stored in a buffer that
// is allocated once on the first vdb_begin call, and stays a fixed
// size is given below in number-of-bytes. If you are sending large
// messages from the browser back to the application you can define
// your own recv buffer size before #including vdb.
#ifndef VDB_RECV_BUFFER_SIZE
#define VDB_RECV_BUFFER_SIZE (1024*1024)
#endif

#ifndef VDB_LISTEN_PORT
#define VDB_LISTEN_PORT 8000
#endif

#if VDB_LISTEN_PORT < 1024 || VDB_LISTEN_PORT > 65535
#error "[vdb] The specified listen port is outside of the valid range (1024-65535)"
#endif

#define VDB_LITTLE_ENDIAN
#if !defined(VDB_LITTLE_ENDIAN) && !defined(VDB_BIG_ENDIAN)
#error "You must define either VDB_LITTLE_ENDIAN or VDB_BIG_ENDIAN"
#endif

#define VDB_LABEL_LENGTH 16
typedef struct
{
    char chars[VDB_LABEL_LENGTH+1];
} vdb_label_t;

#define VDB_MAX_VAR_COUNT 1024
typedef struct
{
    vdb_label_t var_label[VDB_MAX_VAR_COUNT];
    float       var_value[VDB_MAX_VAR_COUNT];
    int         var_count;

    int         flag_continue;

    int         mouse_click;
    float       mouse_click_x;
    float       mouse_click_y;
} vdb_status_t;

typedef struct
{
    #ifdef VDB_WINDOWS
    volatile HANDLE send_semaphore;
    volatile LONG busy;
    volatile int bytes_to_send;
    #else
    int bytes_to_send;
    pid_t recv_pid;
    pid_t send_pid;
    // These pipes are used for flow control between the main thread and the sending thread
    // The sending thread blocks on a read on pipe_ready, until the main thread signals the
    // pipe by write on pipe_ready. The main thread checks if sending is complete by polling
    // (non-blocking) pipe_done, which is signalled by the sending thread.
    int ready[2]; // [0]: read, [1]: send
    int done[2];// [0]: read, [1]: send
    #endif

    int has_send_thread;
    int critical_error;
    int has_connection;
    int work_buffer_used;
    char swapbuffer1[VDB_WORK_BUFFER_SIZE];
    char swapbuffer2[VDB_WORK_BUFFER_SIZE];
    char *work_buffer;
    char *send_buffer;

    char recv_buffer[VDB_RECV_BUFFER_SIZE];

    vdb_status_t status;
} vdb_shared_t;

static vdb_shared_t *vdb_shared = 0;

int vdb_cmp_label(vdb_label_t *a, vdb_label_t *b)
{
    int i;
    for (i = 0; i < VDB_LABEL_LENGTH; i++)
        if (a->chars[i] != b->chars[i])
            return 0;
    return 1;
}

void vdb_copy_label(vdb_label_t *dst, const char *src)
{
    int i = 0;
    while (i < VDB_LABEL_LENGTH && src[i])
    {
        dst->chars[i] = src[i];
        i++;
    }
    while (i < VDB_LABEL_LENGTH)
    {
        dst->chars[i] = ' ';
        i++;
    }
    dst->chars[VDB_LABEL_LENGTH] = 0;
}

#ifdef VDB_RELEASE
// This variable will be defined at the bottom of the concatenated header file
// upon running the make_release_lib program.
extern const char *vdb_html_page;
const char *get_vdb_html_page() { return vdb_html_page; }
#else
// If we are not the release version, we will load app.html from disk and serve that
const char *get_vdb_html_page()
{
    static char static_buffer[1024*1024];
    FILE *file = fopen("../app.html", "rb"); // @ todo: robust file reading
    vdb_assert(file);
    fread(static_buffer, 1, 1024*1024, file); // @ todo: robust file reading
    fclose(file);
    return static_buffer;
}
#endif


// Begin auto-include tcp.c
// interface
int tcp_listen(int port);
int tcp_accept();
int tcp_shutdown();
int tcp_send(const void *data, int size, int *sent_bytes);
int tcp_recv(void *buffer, int capacity, int *read_bytes);
int tcp_sendall(const void *data, int size);

// implementation
#if defined(_WIN32) || defined(_WIN64)

#define TCP_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define TCP_INVALID_SOCKET INVALID_SOCKET
#define TCP_SOCKET_ERROR SOCKET_ERROR
#define tcp_cleanup() WSACleanup()
#define tcp_close(s) closesocket(s)
#define tcp_socket_t SOCKET

#else

#define TCP_UNIX
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#define TCP_INVALID_SOCKET -1
#define TCP_SOCKET_ERROR -1
#define tcp_cleanup()
#define tcp_close(s) close(s)
#define tcp_socket_t int

#endif

static tcp_socket_t tcp_client_socket = 0;
static tcp_socket_t tcp_listen_socket = 0;
static int tcp_has_client_socket = 0;
static int tcp_has_listen_socket = 0;

#ifdef TCP_WINDOWS
int tcp_init()
{
    struct WSAData wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != NO_ERROR)
        return 0;
    return 1;
}
#else
int tcp_init() { return 1; }
#endif

int tcp_listen(int listen_port)
{
    #if 1 // INADDRY_ANY strategy

    int enable_reuse = 1;
    struct sockaddr_in addr = {0};
    tcp_has_listen_socket = 0;

    if (!tcp_init())
        return 0;

    tcp_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_listen_socket == TCP_INVALID_SOCKET)
    {
        tcp_cleanup();
        return 0;
    }

    if (setsockopt(tcp_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable_reuse, sizeof(int)) == TCP_SOCKET_ERROR)
    {
        tcp_close(tcp_listen_socket);
        tcp_cleanup();
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)listen_port);
    if (bind(tcp_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == TCP_SOCKET_ERROR)
    {
        tcp_close(tcp_listen_socket);
        tcp_cleanup();
        return 0;
    }

    if (listen(tcp_listen_socket, 1) == TCP_SOCKET_ERROR)
    {
        tcp_close(tcp_listen_socket);
        tcp_cleanup();
        return 0;
    }
    tcp_has_listen_socket = 1;
    return tcp_has_listen_socket;

    #else // Search for first available address strategy

    struct addrinfo *a = 0;
    struct addrinfo *info = 0;
    struct addrinfo hints = {0};
    char listen_port_str[64];
    sprintf(listen_port_str, "%d", listen_port);

    tcp_has_listen_socket = 0;

    #ifdef TCP_WINDOWS
    struct WSAData wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != NO_ERROR)
        return 0;
    #endif

    // Fetch available addresses
    hints.ai_family = AF_UNSPEC; // Don't care if ipv4 or ipv6
    hints.ai_socktype = SOCK_STREAM; // Tcp
    hints.ai_flags = AI_PASSIVE; // Arbitrary IP?
    if (getaddrinfo(0, listen_port_str, &hints, &info) != 0)
        return 0;

    // Bind socket to first available
    for (a = info; a != 0; a = a->ai_next)
    {
        #ifdef TCP_WINDOWS
        DWORD yes = 1;
        #else
        int yes = 1;
        #endif
        int port = 0;

        if (a->ai_addr->sa_family == AF_INET)
            port = ntohs((int)((struct sockaddr_in*)a->ai_addr)->sin_port);
        else
            port = ntohs((int)((struct sockaddr_in6*)a->ai_addr)->sin6_port);
        if (port != listen_port)
            continue;

        tcp_listen_socket = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (tcp_listen_socket == TCP_INVALID_SOCKET)
            continue;

        if (setsockopt(tcp_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes)) == TCP_SOCKET_ERROR)
        {
            tcp_close(tcp_listen_socket);
            tcp_cleanup();
            continue;
        }

        if (bind(tcp_listen_socket, a->ai_addr, (int)a->ai_addrlen) == TCP_SOCKET_ERROR)
        {
            tcp_close(tcp_listen_socket);
            tcp_cleanup();
            continue;
        }
        if (listen(tcp_listen_socket, 1) == TCP_SOCKET_ERROR)
        {
            tcp_close(tcp_listen_socket);
            tcp_cleanup();
            continue;
        }
        tcp_has_listen_socket = 1;
        break;
    }
    freeaddrinfo(info);
    return tcp_has_listen_socket;
    #endif
}

int tcp_accept()
{
    tcp_client_socket = accept(tcp_listen_socket, 0, 0);
    if (tcp_client_socket == TCP_INVALID_SOCKET)
    {
        tcp_close(tcp_listen_socket);
        tcp_cleanup();
        return 0;
    }
    tcp_has_client_socket = 1;
    return 1;
}

int tcp_shutdown()
{
    if (tcp_has_client_socket) tcp_close(tcp_client_socket);
    if (tcp_has_listen_socket) tcp_close(tcp_listen_socket);
    tcp_has_client_socket = 0;
    tcp_has_listen_socket = 0;
    tcp_cleanup();
    return 1;
}

int tcp_close_client()
{
    tcp_has_client_socket = 0;
    tcp_close(tcp_client_socket);
    return 1;
}

int tcp_send(const void *data, int size, int *sent_bytes)
{
    *sent_bytes = send(tcp_client_socket, (const char*)data, size, 0);
    if (*sent_bytes >= 0) return 1;
    else return 0;
}

int tcp_recv(void *buffer, int capacity, int *read_bytes)
{
    *read_bytes = recv(tcp_client_socket, (char*)buffer, capacity, 0);
    if (*read_bytes > 0) return 1;
    else return 0;
}

int tcp_sendall(const void *buffer, int bytes_to_send)
{
    int sent;
    int remaining = bytes_to_send;
    const char *ptr = (const char*)buffer;
    while (remaining > 0)
    {
        if (!tcp_send(ptr, remaining, &sent))
            return 0;
        remaining -= sent;
        ptr += sent;
        if (remaining < 0)
            return 0;
    }
    return 1;
}

// End auto-include tcp.c

// Begin auto-include websocket.c
// websocket.c - Version 1 - Websocket utilities

// interface
typedef struct
{
    char *payload;
    int length;
    int fin;
    int opcode;
} vdb_msg_t;
int vdb_generate_handshake(const char *request, int request_len, char **out_response, int *out_length);
int vdb_self_test();
void vdb_form_frame(int length, int opcode, unsigned char **out_frame, int *out_length);
int vdb_parse_message(void *recv_buffer, int received, vdb_msg_t *msg);

// implementation
#define MBEDTLS_SHA1_C

// Begin auto-include sha1.c
/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 */

#if defined(MBEDTLS_SHA1_C)

// Begin auto-include sha1.h
/**
 * \file sha1.h
 *
 * \brief SHA-1 cryptographic hash function
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_SHA1_H
#define MBEDTLS_SHA1_H

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SHA1_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA-1 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_sha1_context;

/**
 * \brief          Initialize SHA-1 context
 *
 * \param ctx      SHA-1 context to be initialized
 */
void mbedtls_sha1_init( mbedtls_sha1_context *ctx );

/**
 * \brief          Clear SHA-1 context
 *
 * \param ctx      SHA-1 context to be cleared
 */
void mbedtls_sha1_free( mbedtls_sha1_context *ctx );

/**
 * \brief          Clone (the state of) a SHA-1 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_sha1_clone( mbedtls_sha1_context *dst,
                         const mbedtls_sha1_context *src );

/**
 * \brief          SHA-1 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_sha1_starts( mbedtls_sha1_context *ctx );

/**
 * \brief          SHA-1 process buffer
 *
 * \param ctx      SHA-1 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_sha1_update( mbedtls_sha1_context *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief          SHA-1 final digest
 *
 * \param ctx      SHA-1 context
 * \param output   SHA-1 checksum result
 */
void mbedtls_sha1_finish( mbedtls_sha1_context *ctx, unsigned char output[20] );

/* Internal use */
void mbedtls_sha1_process( mbedtls_sha1_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHA1_ALT */
// #include "sha1_alt.h"
#endif /* MBEDTLS_SHA1_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = SHA-1( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-1 checksum result
 */
void mbedtls_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_sha1_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha1.h */

// End auto-include sha1.h
#include <string.h>

#if !defined(MBEDTLS_SHA1_ALT)

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

void mbedtls_sha1_init( mbedtls_sha1_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_sha1_context ) );
}

void mbedtls_sha1_free( mbedtls_sha1_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_sha1_context ) );
}

void mbedtls_sha1_clone( mbedtls_sha1_context *dst,
                         const mbedtls_sha1_context *src )
{
    *dst = *src;
}

/*
 * SHA-1 context setup
 */
void mbedtls_sha1_starts( mbedtls_sha1_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

#if !defined(MBEDTLS_SHA1_PROCESS_ALT)
void mbedtls_sha1_process( mbedtls_sha1_context *ctx, const unsigned char data[64] )
{
    uint32_t temp, W[16], A, B, C, D, E;

    GET_UINT32_BE( W[ 0], data,  0 );
    GET_UINT32_BE( W[ 1], data,  4 );
    GET_UINT32_BE( W[ 2], data,  8 );
    GET_UINT32_BE( W[ 3], data, 12 );
    GET_UINT32_BE( W[ 4], data, 16 );
    GET_UINT32_BE( W[ 5], data, 20 );
    GET_UINT32_BE( W[ 6], data, 24 );
    GET_UINT32_BE( W[ 7], data, 28 );
    GET_UINT32_BE( W[ 8], data, 32 );
    GET_UINT32_BE( W[ 9], data, 36 );
    GET_UINT32_BE( W[10], data, 40 );
    GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 );
    GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 );
    GET_UINT32_BE( W[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[( t -  3 ) & 0x0F] ^ W[( t - 8 ) & 0x0F] ^ \
           W[( t - 14 ) & 0x0F] ^ W[  t       & 0x0F],  \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}
#endif /* !MBEDTLS_SHA1_PROCESS_ALT */

/*
 * SHA-1 process buffer
 */
void mbedtls_sha1_update( mbedtls_sha1_context *ctx, const unsigned char *input, size_t ilen )
{
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        mbedtls_sha1_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        mbedtls_sha1_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );
}

static const unsigned char sha1_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-1 final digest
 */
void mbedtls_sha1_finish( mbedtls_sha1_context *ctx, unsigned char output[20] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( high, msglen, 0 );
    PUT_UINT32_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    mbedtls_sha1_update( ctx, sha1_padding, padn );
    mbedtls_sha1_update( ctx, msglen, 8 );

    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );
}

#endif /* !MBEDTLS_SHA1_ALT */

/*
 * output = SHA-1( input buffer )
 */
void mbedtls_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
    mbedtls_sha1_context ctx;

    mbedtls_sha1_init( &ctx );
    mbedtls_sha1_starts( &ctx );
    mbedtls_sha1_update( &ctx, input, ilen );
    mbedtls_sha1_finish( &ctx, output );
    mbedtls_sha1_free( &ctx );
}

#if defined(MBEDTLS_SELF_TEST)
/*
 * FIPS-180-1 test vectors
 */
static const unsigned char sha1_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const int sha1_test_buflen[3] =
{
    3, 56, 1000
};

static const unsigned char sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};

/*
 * Checkup routine
 */
int mbedtls_sha1_self_test( int verbose )
{
    int i, j, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha1sum[20];
    mbedtls_sha1_context ctx;

    mbedtls_sha1_init( &ctx );

    /*
     * SHA-1
     */
    for( i = 0; i < 3; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  SHA-1 test #%d: ", i + 1 );

        mbedtls_sha1_starts( &ctx );

        if( i == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                mbedtls_sha1_update( &ctx, buf, buflen );
        }
        else
            mbedtls_sha1_update( &ctx, sha1_test_buf[i],
                               sha1_test_buflen[i] );

        mbedtls_sha1_finish( &ctx, sha1sum );

        if( memcmp( sha1sum, sha1_test_sum[i], 20 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_sha1_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SHA1_C */

// End auto-include sha1.h

int vdb_extract_user_key(const char *request, int request_len, char *key)
{
    // The user request contains this string somewhere in it:
    // "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", This
    // code extracts the "dGhlIHNhbXBsZSBub25jZQ==" part.
    int i,j;
    int key_len = 0;
    const char *pattern = "Sec-WebSocket-Key:";
    int pattern_len = (int)strlen(pattern);
    vdb_assert(request_len >= pattern_len);
    for (i = 0; i < request_len-pattern_len; i++)
    {
        int is_equal = 1;
        for (j = 0; j < pattern_len; j++)
        {
            if (request[i+j] != pattern[j])
                is_equal = 0;
        }
        if (is_equal)
        {
            const char *src = request + i + pattern_len + 1;
            while (*src && *src != '\r')
            {
                key[key_len++] = *src;
                src++;
            }
        }
    }
    return key_len;
}

int vdb_generate_accept_key(const char *request, int request_len, char *accept_key)
{
    // The WebSocket standard has defined that the server must respond to a connection
    // request with a hash key that is generated from the user's key. This code implements
    // the stuff in https://tools.ietf.org/html/rfc6455#section-1.3
    char user_key[1024] = {0};
    unsigned char new_key[1024] = {0};
    int user_len = 0;
    int new_len = 0;

    user_len = vdb_extract_user_key(request, request_len, user_key);
    vdb_assert(user_len > 0);

    // Concatenate salt and user keys
    {
        const char *salt = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        int salt_len = (int)strlen(salt);
        for (new_len = 0; new_len < user_len; new_len++)
            new_key[new_len] = (unsigned char)user_key[new_len];
        for (; new_len < user_len + salt_len; new_len++)
            new_key[new_len] = (unsigned char)salt[new_len-user_len];
    }

    // Compute the accept-key
    {
        // Compute sha1 hash
        unsigned char sha1[20];
        mbedtls_sha1(new_key, (size_t)new_len, sha1);

        // Convert to base64 null-terminated string
        {
            const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            unsigned char x1, x2, x3;
            int i;
            for (i = 2; i <= 20; i += 3)
            {
                x3 = (i < 20) ? sha1[i] : 0;
                x2 = sha1[i-1];
                x1 = sha1[i-2];
                *accept_key++ = b64[((x1 >> 2) & 63)];
                *accept_key++ = b64[((x1 &  3) << 4) | ((x2 >> 4) & 15)];
                *accept_key++ = b64[((x2 & 15) << 2) | ((x3 >> 6) & 3)];
                *accept_key++ = (i < 20) ? b64[((x3 >> 0) & 63)] : '=';
            }
            *accept_key = 0;
        }
    }

    return 1;
}

int vdb_generate_handshake(const char *request, int request_len, char **out_response, int *out_length)
{
    const char *header1 =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: ";
    const char *header2 = "\r\n\r\n";
    char accept_key[1024];
    static char response[1024];
    int response_len = 0;
    size_t i = 0;

    vdb_assert(vdb_generate_accept_key(request, request_len, accept_key));
    for (i = 0; i < strlen(header1); i++)    response[response_len++] = header1[i];
    for (i = 0; i < strlen(accept_key); i++) response[response_len++] = accept_key[i];
    for (i = 0; i < strlen(header2); i++)    response[response_len++] = header2[i];

    *out_response = response;
    *out_length = response_len;
    return 1;
}

int vdb_self_test()
{
    int request_len;
    char accept_key[1024];
    const char *request =
        "GET /chat HTTP/1.1\r\n"
        "Host: server.example.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: chat, superchat\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: http://example.com\r\n\r\n";
    request_len = (int)strlen(request);
    vdb_generate_accept_key(request, request_len, accept_key);
    vdb_assert(strcmp(accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
    return 1;
}

void vdb_print_bytes(void *recv_buffer, int n)
{
    int index;
    for (index = 0; index < n; index++)
    {
        unsigned char c = ((unsigned char*)recv_buffer)[index];
        int i;
        printf("%d:\t", index);
        for (i = 7; i >= 4; i--) printf("%d", (c >> i) & 1);
        printf(" ");
        for (i = 3; i >= 0; i--) printf("%d", (c >> i) & 1);
        printf("\n");
    }
}

// opcode = 0x2 for binary data
// opcode = 0x8 for closing handshakes
void vdb_form_frame(int length, int opcode, unsigned char **out_frame, int *out_length)
{
    static unsigned char frame[16] = {0};
    int frame_length = 0;
    {
        // fin rsv1 rsv2 rsv3 opcode
        // 1   0    0    0     xxxx
        frame[0] = (1 << 7) | (opcode & 0xF);
        if (length <= 125)
        {
            frame[1] = (unsigned char)(length & 0xFF);
            frame_length = 2;
        }
        else if (length <= 65535)
        {
            frame[1] = 126;
            frame[2] = (unsigned char)((length >> 8) & 0xFF);
            frame[3] = (unsigned char)((length >> 0) & 0xFF);
            frame_length = 4;
        }
        else
        {
            frame[1] = 127;
            frame[2] = 0; // @ assuming length is max 32 bit
            frame[3] = 0; // @ assuming length is max 32 bit
            frame[4] = 0; // @ assuming length is max 32 bit
            frame[5] = 0; // @ assuming length is max 32 bit
            frame[6] = (length >> 24) & 0xFF;
            frame[7] = (length >> 16) & 0xFF;
            frame[8] = (length >>  8) & 0xFF;
            frame[9] = (length >>  0) & 0xFF;
            frame_length = 10;
        }
    }
    *out_frame = frame;
    *out_length = frame_length;
}

int vdb_parse_message(void *recv_buffer, int received, vdb_msg_t *msg)
{
    // https://tools.ietf.org/html/rfc6455#section-5.4
    // Note: WebSocket does not send fields unless
    // they are needed. For example, extended len
    // is not sent if the len fits inside payload
    // len.
    uint32_t opcode;
    uint32_t fin;
    uint64_t len;
    uint32_t mask;
    unsigned char key[4] = {0};
    unsigned char *frame = (unsigned char*)recv_buffer;
    int i = 0;

    // extract header
    vdb_assert(i + 2 <= received);
    opcode = ((frame[i  ] >> 0) & 0xF);
    fin    = ((frame[i++] >> 7) & 0x1);
    len    = ((frame[i  ] >> 0) & 0x7F);
    mask   = ((frame[i++] >> 7) & 0x1);

    // client messages must be masked according to spec
    vdb_assert(mask == 1);

    // extract payload length in number of bytes
    if (len == 126)
    {
        vdb_assert(i + 2 <= received);
        len = 0;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++];
    }
    else if (len == 127)
    {
        vdb_assert(i + 8 <= received);
        len = 0;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++]; len <<= 8;
        len |= frame[i++];
    }

    // verify that we read the length correctly
    vdb_assert(len <= (uint64_t)received);

    // extract key used to decode payload
    {
        vdb_assert(i + 4 <= received);
        key[0] = frame[i++];
        key[1] = frame[i++];
        key[2] = frame[i++];
        key[3] = frame[i++];
    }

    // decode payload
    {
        int j = 0;
        vdb_assert(i + (int)len <= received);
        for (j = 0; j < (int)len; j++)
            frame[i+j] = frame[i+j] ^ key[j % 4];
        frame[i+len] = 0;
    }

    msg->payload = (char*)(frame + i);
    msg->length = (int)len;
    msg->opcode = (int)opcode;
    msg->fin = (int)fin;
    return 1;
}

// End auto-include sha1.h

// Begin auto-include vdb_handle_message.c

// This is used by vdb_recv_thread (vdb_network_threads.c) whenever
// we get a valid message from the client. The client periodically
// sends status updates at a fixed rate, and some asynchronous events
// (like mouse clicks and button presses).

// Returns true (1) if we successfully parsed the message
// or if we did not recognize it. Returns false (0) if something
// unexpected happened while parsing the message.
int vdb_handle_message(vdb_msg_t msg, vdb_status_t *status)
{
    vdb_status_t new_status = *status;

    // vdb_log("Got a message (%d): '%s'\n", msg.length, msg.payload);
    // This means the user pressed the 'continue' button
    if (msg.length == 1 && msg.payload[0] == 'c')
    {
        new_status.flag_continue = 1;
    }

    // Mouse click event
    if (msg.length > 1 && msg.payload[0] == 'm')
    {
        float x, y;
        vdb_assert(sscanf(msg.payload+1, "%f%f", &x, &y) == 2);
        new_status.mouse_click = 1;
        new_status.mouse_click_x = x;
        new_status.mouse_click_y = y;
    }

    // This is a status update that is sent at regular intervals
    if (msg.length > 1 && msg.payload[0] == 's')
    {
        char *str = msg.payload;
        int pos = 0 + 2;
        int got = 0;
        int i;
        int n;

        // read 'number of variables'
        vdb_assert(sscanf(str+pos, "%d%n", &n, &got) == 1);
        vdb_assert(n >= 0 && n < VDB_MAX_VAR_COUNT);

        // if there are no variables we are done!
        if (n == 0)
            return 1;

        pos += got+1; // read past int and space
        vdb_assert(pos < msg.length);

        for (i = 0; i < n; i++)
        {
            vdb_label_t label;
            float value;

            // read label
            vdb_assert(pos + VDB_LABEL_LENGTH < msg.length);
            vdb_copy_label(&label, str+pos);
            pos += VDB_LABEL_LENGTH;

            // read value
            vdb_assert(sscanf(str+pos, "%f%n", &value, &got) == 1);
            pos += got+1; // read past float and space

            // update variable @ ROBUSTNESS @ RACE CONDITION
            new_status.var_label[i] = label;
            new_status.var_value[i] = value;
        }
        new_status.var_count = n;
    }

    *status = new_status;
    return 1;
}

// End auto-include vdb_handle_message.c

// Begin auto-include vdb_network_threads.c
#ifdef VDB_WINDOWS
int vdb_wait_data_ready()
{
    WaitForSingleObject(vdb_shared->send_semaphore, INFINITE);
    while (InterlockedCompareExchange(&vdb_shared->busy, 1, 0) == 1)
    {
        vdb_log("CompareExchange blocked\n");
    }
    return 1;
}
int vdb_signal_data_sent()  { vdb_shared->busy = 0; return 1; }
int vdb_poll_data_sent()    { return (InterlockedCompareExchange(&vdb_shared->busy, 1, 0) == 0); }
int vdb_signal_data_ready() { vdb_shared->busy = 0; ReleaseSemaphore(vdb_shared->send_semaphore, 1, 0); return 1; } // @ mfence, writefence
void vdb_sleep(int ms)      { Sleep(ms); }
#else
int vdb_wait_data_ready()   { int val = 0; return  read(vdb_shared->ready[0], &val, sizeof(val)) == sizeof(val); }
int vdb_poll_data_sent()    { int val = 0; return   read(vdb_shared->done[0], &val, sizeof(val)) == sizeof(val); }
int vdb_signal_data_ready() { int one = 1; return write(vdb_shared->ready[1], &one, sizeof(one)) == sizeof(one); }
int vdb_signal_data_sent()  { int one = 1; return  write(vdb_shared->done[1], &one, sizeof(one)) == sizeof(one); }
void vdb_sleep(int ms)      { usleep(ms*1000); }
#endif

int vdb_send_thread()
{
    vdb_shared_t *vs = vdb_shared;
    unsigned char *frame; // @ UGLY: form_frame should modify a char *?
    int frame_len;
    vdb_log("Created send thread\n");
    vdb_sleep(100); // @ RACECOND: Let the parent thread set has_send_thread to 1
    while (!vs->critical_error)
    {
        // blocking until data is signalled ready from main thread
        vdb_critical(vdb_wait_data_ready());

        // send frame header (0x2 indicating binary data)
        vdb_form_frame(vs->bytes_to_send, 0x2, &frame, &frame_len);
        if (!tcp_sendall(frame, frame_len))
        {
            vdb_log("Failed to send frame\n");
            vdb_critical(vdb_signal_data_sent());
            break;
        }

        // send the payload
        if (!tcp_sendall(vs->send_buffer, vs->bytes_to_send))
        {
            vdb_log("Failed to send payload\n");
            vdb_critical(vdb_signal_data_sent());
            break;
        }

        // signal to main thread that data has been sent
        vdb_critical(vdb_signal_data_sent());
    }
    vs->has_send_thread = 0;
    return 0;
}

#ifdef VDB_WINDOWS
DWORD WINAPI vdb_win_send_thread(void *vdata) { (void)(vdata); return vdb_send_thread(); }
#endif

int vdb_strcmpn(const char *a, const char *b, int len)
{
    int i;
    for (i = 0; i < len; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

int vdb_is_http_request(const char *str, int len)
{
    // First three characters must be "GET"
    const char *s = "GET";
    int n = (int)strlen(s);
    if (len >= n && vdb_strcmpn(str, s, n))
        return 1;
    return 0;
}

int vdb_is_websockets_request(const char *str, int len)
{
    // "Upgrade: websocket" must occur somewhere
    const char *s = "websocket";
    int n = (int)strlen(s);
    int i = 0;
    for (i = 0; i < len - n; i++)
        if (vdb_strcmpn(str + i, s, n))
            return 1;
    return 0;
}

int vdb_recv_thread()
{
    vdb_shared_t *vs = vdb_shared;
    int read_bytes;
    vdb_msg_t msg;
    vdb_log("Created read thread\n");
    while (!vs->critical_error)
    {
        if (vs->critical_error)
        {
            return 0;
        }
        if (!tcp_has_listen_socket)
        {
            vdb_log("Creating listen socket\n");
            if (!tcp_listen(VDB_LISTEN_PORT))
            {
                vdb_log("Failed to create socket on port %d\n", VDB_LISTEN_PORT);
                vdb_sleep(1000);
                continue;
            }
            vdb_log_once("Visualization is live at host:%d\n", VDB_LISTEN_PORT);
        }
        if (!tcp_has_client_socket)
        {
            vdb_log("Waiting for client\n");
            if (!tcp_accept())
            {
                vdb_sleep(1000);
                continue;
            }
        }
        if (!vs->has_connection)
        {
            int is_http_request;
            int is_websocket_request;
            vdb_log("Waiting for handshake\n");
            if (!tcp_recv(vs->recv_buffer, VDB_RECV_BUFFER_SIZE, &read_bytes))
            {
                vdb_log("Lost connection during handshake\n");
                tcp_shutdown();
                vdb_sleep(1000);
                continue;
            }

            is_http_request = vdb_is_http_request(vs->recv_buffer, read_bytes);
            is_websocket_request = vdb_is_websockets_request(vs->recv_buffer, read_bytes);

            if (!is_http_request)
            {
                vdb_log("Got an invalid HTTP request while waiting for handshake\n");
                tcp_shutdown();
                vdb_sleep(1000);
                continue;
            }

            // If it was not a websocket HTTP request we will send the HTML page
            if (!is_websocket_request)
            {
                const char *content = get_vdb_html_page();
                static char http_response[1024*1024];
                int len = sprintf(http_response,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: %d\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: Closed\r\n\r\n%s",
                    (int)strlen(content), content);

                vdb_log("Sending HTML page.\n");
                if (!tcp_sendall(http_response, len))
                {
                    vdb_log("Lost connection while sending HTML page\n");
                    tcp_shutdown();
                    vdb_sleep(1000);
                    continue;
                }

                // Sending 'Connection: Closed' allows us to close the socket immediately
                tcp_close_client();

                vdb_sleep(1000);
                continue;
            }

            // Otherwise we will set up the Websockets connection
            {
                char *response;
                int response_len;

                vdb_log("Generating WebSockets key\n");
                if (!vdb_generate_handshake(vs->recv_buffer, read_bytes, &response, &response_len))
                {
                    vdb_log("Failed to generate WebSockets handshake key. Retrying.\n");
                    tcp_shutdown();
                    vdb_sleep(1000);
                    continue;
                }

                vdb_log("Sending WebSockets handshake\n");
                if (!tcp_sendall(response, response_len))
                {
                    vdb_log("Connection went down while setting up WebSockets connection. Retrying.\n");
                    tcp_shutdown();
                    vdb_sleep(1000);
                    continue;
                }

                vs->has_connection = 1;
            }
        }
        #ifdef VDB_UNIX
        // The send thread is allowed to return on unix, because if the connection
        // goes down, the recv thread needs to respawn the process after a new
        // client connection has been acquired (to share the file descriptor).
        // fork() shares the open file descriptors with the child process, but
        // if a file descriptor is _then_ opened in the parent, it will _not_
        // be shared with the child.
        if (!vs->has_send_thread)
        {
            vs->send_pid = fork();
            vdb_critical(vs->send_pid != -1);
            if (vs->send_pid == 0)
            {
                signal(SIGTERM, SIG_DFL); // Clear inherited signal handlers
                vdb_send_thread(); // vdb_send_thread sets has_send_thread to 0 upon returning
                _exit(0);
            }
            vs->has_send_thread = 1;
        }
        #else
        // Because we allow it to return on unix, we allow it to return on windows
        // as well, even though file descriptors are shared anyway.
        if (!vs->has_send_thread)
        {
            CreateThread(0, 0, vdb_win_send_thread, NULL, 0, 0); // vdb_send_thread sets has_send_thread to 0 upon returning
            vs->has_send_thread = 1;
        }
        #endif

        if (!tcp_recv(vs->recv_buffer, VDB_RECV_BUFFER_SIZE, &read_bytes)) // @ INCOMPLETE: Assemble frames
        {
            vdb_log("Connection went down\n");
            vs->has_connection = 0;
            tcp_shutdown();
            #ifdef VDB_UNIX
            if (vs->has_send_thread)
            {
                kill(vs->send_pid, SIGUSR1);
                vs->has_send_thread = 0;
            }
            #endif
            vdb_sleep(100);
            continue;
        }
        if (!vdb_parse_message(vs->recv_buffer, read_bytes, &msg))
        {
            vdb_log("Got a bad message\n");
            continue;
        }
        if (!msg.fin)
        {
            vdb_log("Got an incomplete message (%d): '%s'\n", msg.length, msg.payload);
            continue;
        }
        if (msg.opcode == 0x8) // closing handshake
        {
            unsigned char *frame = 0;
            int frame_len = 0;
            vdb_log("Client voluntarily disconnected\n");
            vdb_form_frame(0, 0x8, &frame, &frame_len);
            if (!tcp_sendall(frame, frame_len))
                vdb_log("Failed to send closing handshake\n");
            continue;
        }
        if (!vdb_handle_message(msg, &vs->status))
        {
            vdb_log("Handled a bad message\n");
            continue;
        }
    }
    return 0;
}

#ifdef VDB_WINDOWS
DWORD WINAPI vdb_win_recv_thread(void *vdata) { (void)(vdata); return vdb_recv_thread(); }
#endif

// End auto-include vdb_network_threads.c

// Begin auto-include vdb_push_buffer.c
// Reserve 'count' number of bytes in the work buffer and optionally
// initialize their values to 'data', if 'data' is not NULL. Returns
// a pointer to the beginning of the reserved memory if there was
// space left, NULL otherwise.
void *vdb_push_bytes(const void *data, int count)
{
    if (vdb_shared->work_buffer_used + count <= VDB_WORK_BUFFER_SIZE)
    {
        const char *src = (const char*)data;
              char *dst = vdb_shared->work_buffer + vdb_shared->work_buffer_used;
        if (src) memcpy(dst, src, count);
        else     memset(dst, 0, count);
        vdb_shared->work_buffer_used += count;
        return (void*)dst;
    }
    return NULL;
}

// Reserve just enough memory for a single variable type. Might be
// more efficient than calling push_bytes if you have a lot of small
// types. I'm sorry that this is a macro; specialized functions for
// common types are given below.
#define _vdb_push_type(VALUE, TYPE)                                                  \
    if (vdb_shared->work_buffer_used + sizeof(TYPE) <= VDB_WORK_BUFFER_SIZE)         \
    {                                                                                \
        TYPE *ptr = (TYPE*)(vdb_shared->work_buffer + vdb_shared->work_buffer_used); \
        vdb_shared->work_buffer_used += sizeof(TYPE);                                \
        *ptr = VALUE;                                                                \
        return ptr;                                                                  \
    }                                                                                \
    return NULL;

uint8_t  *vdb_push_u08(uint8_t x)  { _vdb_push_type(x, uint8_t);  }
uint32_t *vdb_push_u32(uint32_t x) { _vdb_push_type(x, uint32_t); }
float    *vdb_push_r32(float x)    { _vdb_push_type(x, float);    }

// End auto-include vdb_push_buffer.c

// Begin auto-include vdb_draw_commands.c
#define vdb_color_mode_primary  0
#define vdb_color_mode_ramp     1

#define vdb_mode_point2         1
#define vdb_mode_point3         2
#define vdb_mode_line2          3
#define vdb_mode_line3          4
#define vdb_mode_fill_rect      5
#define vdb_mode_circle         6
#define vdb_mode_image_rgb8     7
#define vdb_mode_slider         254

static unsigned char vdb_current_color_mode = 0;
static unsigned char vdb_current_color = 0;
static unsigned char vdb_current_alpha = 0;

static float *vdb_point_size = 0;
static float *vdb_line_size = 0;
static float *vdb_alpha_value = 0;
static unsigned char *vdb_nice_points = 0;

static float vdb_xrange_left = -1.0f;
static float vdb_xrange_right = +1.0f;
static float vdb_yrange_bottom = -1.0f;
static float vdb_yrange_top = +1.0f;
static float vdb_zrange_far = -1.0f;
static float vdb_zrange_near = +1.0f;

// This function is automatically called on a successful vdb_begin call
// to let you set up whatever state before beginning to submit commands.
void vdb_begin_submission()
{
    vdb_current_color_mode = vdb_color_mode_primary;
    vdb_current_alpha = 0;
    vdb_xrange_left = -1.0f;
    vdb_xrange_right = +1.0f;
    vdb_yrange_bottom = -1.0f;
    vdb_yrange_top = +1.0f;
    vdb_zrange_far = -1.0f;
    vdb_zrange_near = +1.0f;

    // Reserve the immediately first portion of the work buffer
    // for geometry-global variables
    vdb_point_size = vdb_push_r32(4.0f);
    vdb_line_size = vdb_push_r32(2.0f);
    vdb_alpha_value = vdb_push_r32(0.5f);
    vdb_nice_points = vdb_push_u08(0);
}

// This function is automatically called on vdb_end, right before
// the workload is sent off the the network thread.
void vdb_end_submission()
{
    // Mark events as handled
    vdb_shared->status.mouse_click = 0;
}

void vdb_color_primary(int primary, int shade)
{
    if (primary < 0) primary = 0;
    if (primary > 4) primary = 4;
    if (shade < 0) shade = 0;
    if (shade > 2) shade = 2;
    vdb_current_color_mode = vdb_color_mode_primary;
    vdb_current_color = (unsigned char)(3*primary + shade);
}

void vdb_color_rampf(float value)
{
    int i = (int)(value*63.0f);
    if (i < 0) i = 0;
    if (i > 63) i = 63;
    vdb_current_color_mode = vdb_color_mode_ramp;
    vdb_current_color = (unsigned char)i;
}

void vdb_color_ramp(int i)
{
    vdb_current_color_mode = vdb_color_mode_ramp;
    vdb_current_color = (unsigned char)(i % 63);
}

void vdb_color_red(int shade)   { vdb_color_primary(0, shade); }
void vdb_color_green(int shade) { vdb_color_primary(1, shade); }
void vdb_color_blue(int shade)  { vdb_color_primary(2, shade); }
void vdb_color_black(int shade) { vdb_color_primary(3, shade); }
void vdb_color_white(int shade) { vdb_color_primary(4, shade); }
void vdb_translucent()          { vdb_current_alpha = 1; }
void vdb_opaque()               { vdb_current_alpha = 0; }

void vdb_setPointSize(float radius)   { if (vdb_point_size)  *vdb_point_size = radius; }
void vdb_setLineSize(float radius)    { if (vdb_line_size)   *vdb_line_size = radius; }
void vdb_setNicePoints(int enabled)   { if (vdb_nice_points) *vdb_nice_points = (unsigned char)enabled; }
void vdb_setTranslucency(float alpha) { if (vdb_alpha_value) *vdb_alpha_value = alpha; }

void vdb_xrange(float left, float right)
{
    vdb_xrange_left = left;
    vdb_xrange_right = right;
}

void vdb_yrange(float bottom, float top)
{
    vdb_yrange_bottom = bottom;
    vdb_yrange_top = top;
}

void vdb_zrange(float z_near, float z_far)
{
    vdb_zrange_near = z_near;
    vdb_zrange_far = z_far;
}

float vdb__unmap_x(float x) { return vdb_xrange_left + (0.5f+0.5f*x)*(vdb_xrange_right-vdb_xrange_left); }
float vdb__unmap_y(float y) { return vdb_yrange_bottom + (0.5f+0.5f*y)*(vdb_yrange_top-vdb_yrange_bottom); }
float vdb__map_x(float x) { return -1.0f + 2.0f*(x-vdb_xrange_left)/(vdb_xrange_right-vdb_xrange_left); }
float vdb__map_y(float y) { return -1.0f + 2.0f*(y-vdb_yrange_bottom)/(vdb_yrange_top-vdb_yrange_bottom); }
float vdb__map_z(float z) { return +1.0f - 2.0f*(z-vdb_zrange_near)/(vdb_zrange_far-vdb_zrange_near); }

void vdb_push_style()
{
    unsigned char opacity = ((vdb_current_alpha & 0x01)      << 7);
    unsigned char mode    = ((vdb_current_color_mode & 0x01) << 6);
    unsigned char value   = ((vdb_current_color & 0x3F)      << 0);
    unsigned char style   = opacity | mode | value;
    vdb_push_u08(style);
}

void vdb_point(float x, float y)
{
    vdb_push_u08(vdb_mode_point2);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x));
    vdb_push_r32(vdb__map_y(y));
}

void vdb_point3d(float x, float y, float z)
{
    vdb_push_u08(vdb_mode_point3);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x));
    vdb_push_r32(vdb__map_y(y));
    vdb_push_r32(vdb__map_z(z));
}

void vdb_line(float x1, float y1, float x2, float y2)
{
    vdb_push_u08(vdb_mode_line2);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x1));
    vdb_push_r32(vdb__map_y(y1));
    vdb_push_r32(vdb__map_x(x2));
    vdb_push_r32(vdb__map_y(y2));
}

void vdb_line3d(float x1, float y1, float z1, float x2, float y2, float z2)
{
    vdb_push_u08(vdb_mode_line3);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x1));
    vdb_push_r32(vdb__map_y(y1));
    vdb_push_r32(vdb__map_z(z1));
    vdb_push_r32(vdb__map_x(x2));
    vdb_push_r32(vdb__map_y(y2));
    vdb_push_r32(vdb__map_z(z2));
}

void vdb_fillRect(float x, float y, float w, float h)
{
    vdb_push_u08(vdb_mode_fill_rect);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x));
    vdb_push_r32(vdb__map_y(y));
    vdb_push_r32(vdb__map_x(x+w));
    vdb_push_r32(vdb__map_y(y+h));
}

void vdb_circle(float x, float y, float r)
{
    vdb_push_u08(vdb_mode_circle);
    vdb_push_style();
    vdb_push_r32(vdb__map_x(x));
    vdb_push_r32(vdb__map_y(y));
    vdb_push_r32(vdb__map_x(r) - vdb__map_x(0.0f));
    vdb_push_r32(vdb__map_y(r) - vdb__map_y(0.0f));
}

void vdb_imageRGB8(const void *data, int w, int h)
{
    vdb_push_u08(vdb_mode_image_rgb8);
    vdb_push_style();
    vdb_push_u32(w);
    vdb_push_u32(h);
    vdb_push_bytes(data, w*h*3);
}

void vdb_slider1f(const char *in_label, float *x, float min_value, float max_value)
{
    int i = 0;
    vdb_label_t label = {0};
    vdb_copy_label(&label, in_label);
    vdb_push_u08(vdb_mode_slider);
    vdb_push_style();
    vdb_push_bytes(label.chars, VDB_LABEL_LENGTH);
    vdb_push_r32(*x);
    vdb_push_r32(min_value);
    vdb_push_r32(max_value);
    vdb_push_r32(0.01f);

    // Update variable
    // @ ROBUSTNESS @ RACE CONDITION: Mutex on latest message
    for (i = 0; i < vdb_shared->status.var_count; i++)
    {
        if (vdb_cmp_label(&vdb_shared->status.var_label[i], &label))
        {
            float v = vdb_shared->status.var_value[i];
            if (v < min_value) v = min_value;
            if (v > max_value) v = max_value;
            *x = v;
        }
    }
}

void vdb_slider1i(const char *in_label, int *x, int min_value, int max_value)
{
    int i = 0;
    vdb_label_t label = {0};
    vdb_copy_label(&label, in_label);
    vdb_push_u08(vdb_mode_slider);
    vdb_push_style();
    vdb_push_bytes(label.chars, VDB_LABEL_LENGTH);
    vdb_push_r32((float)*x);
    vdb_push_r32((float)min_value);
    vdb_push_r32((float)max_value);
    vdb_push_r32(1.0f);

    // Update variable
    // @ ROBUSTNESS @ RACE CONDITION: Mutex on latest message
    for (i = 0; i < vdb_shared->status.var_count; i++)
    {
        if (vdb_cmp_label(&vdb_shared->status.var_label[i], &label))
        {
            int v = (int)vdb_shared->status.var_value[i];
            if (v < min_value) v = min_value;
            if (v > max_value) v = max_value;
            *x = v;
        }
    }
}

void vdb_checkbox(const char *in_label, int *x)
{
    vdb_slider1i(in_label, x, 0, 1);
}

int vdb_mouse_click(float *x, float *y)
{
    if (vdb_shared->status.mouse_click)
    {
        *x = vdb__unmap_x(vdb_shared->status.mouse_click_x);
        *y = vdb__unmap_y(vdb_shared->status.mouse_click_y);
        return 1;
    }
    return 0;
}

// End auto-include vdb_draw_commands.c

// Begin auto-include vdb_begin_end.c
#ifdef VDB_UNIX
void vdb_unix_atexit()
{
    if (vdb_shared)
    {
        kill(vdb_shared->recv_pid, SIGTERM);
        kill(vdb_shared->send_pid, SIGTERM);
    }
}
#endif

int vdb_begin()
{
    if (!vdb_shared)
    {
        #ifdef VDB_UNIX
        vdb_shared = (vdb_shared_t*)mmap(NULL, sizeof(vdb_shared_t),
                                         PROT_READ|PROT_WRITE,
                                         MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (vdb_shared == MAP_FAILED)
            vdb_shared = 0;
        #else
        vdb_shared = (vdb_shared_t*)calloc(sizeof(vdb_shared_t),1);
        #endif

        if (!vdb_shared)
        {
            vdb_err_once("Tried to allocate too much memory, try lowering VDB_RECV_BUFFER_SIZE and VDB_SEND_BUFFER_SIZE\n");
            return 0;
        }

        #ifdef VDB_UNIX
        atexit(vdb_unix_atexit); // We want to terminate any child processes when we terminate

        vdb_critical(pipe(vdb_shared->ready) != -1);
        vdb_critical(pipe2(vdb_shared->done, O_NONBLOCK) != -1);

        // Create recv process
        vdb_shared->recv_pid = fork();
        vdb_critical(vdb_shared->recv_pid != -1);
        if (vdb_shared->recv_pid == 0)
        {
            signal(SIGTERM, SIG_DFL); // Clear inherited signal handlers
            vdb_recv_thread();
            _exit(0);
        }
        vdb_signal_data_sent(); // Needed for first vdb_end call

        #else
        vdb_shared->send_semaphore = CreateSemaphore(0, 0, 1, 0);
        CreateThread(0, 0, vdb_win_recv_thread, NULL, 0, 0);
        #endif

        vdb_shared->work_buffer = vdb_shared->swapbuffer1;
        vdb_shared->send_buffer = vdb_shared->swapbuffer2;
        // Remaining parameters should be initialized to zero by calloc or mmap
    }
    if (vdb_shared->critical_error)
    {
        vdb_err_once("You must restart your program to use vdb.\n");
        return 0;
    }
    if (!vdb_shared->has_connection)
    {
        return 0;
    }
    vdb_shared->work_buffer_used = 0;
    vdb_begin_submission();
    return 1;
}

void vdb_end()
{
    vdb_shared_t *vs = vdb_shared;
    if (vdb_poll_data_sent()) // Check if send_thread has finished sending data
    {
        vdb_end_submission();

        char *new_work_buffer = vs->send_buffer;
        vs->send_buffer = vs->work_buffer;
        vs->bytes_to_send = vs->work_buffer_used;
        vs->work_buffer = new_work_buffer;
        vs->work_buffer_used = 0;

        // Notify sending thread that data is available
        vdb_signal_data_ready();
    }
}

int vdb_loop(int fps)
{
    static int entry = 1;
    if (entry)
    {
        while (!vdb_begin())
        {
        }
        entry = 0;
    }
    else
    {
        vdb_end();
        vdb_sleep(1000/fps);
        if (vdb_shared->status.flag_continue)
        {
            vdb_shared->status.flag_continue = 0;
            entry = 1;
            return 0;
        }
        while (!vdb_begin())
        {
        }
    }
    return 1;
}

// End auto-include vdb_begin_end.c

// Begin embedded app.html
const char *vdb_html_page = 
"<html>\n"
"<head>\n"
"<title>vdebug</title>\n"
"\n"
"<!-- STYLE BEGIN -->\n"
"<style>\n"
"body {\n"
"    font-family: ubuntu, sans-serif;\n"
"    font-size: 13px;\n"
"    /*background: #fff;*/\n"
"    background: #f1f1f1;\n"
"    margin: 0;\n"
"}\n"
"\n"
"#canvas {\n"
"    border-radius: 4px;\n"
"    background: #fff;\n"
"    box-shadow: 0px 2px 2px #A7A7A7;\n"
"    display: block;\n"
"    margin-left: auto;\n"
"    margin-right: auto;\n"
"    margin-top: 12px;\n"
"    margin-bottom: 12px;\n"
"    width: 100%;\n"
"    height: 320px;\n"
"}\n"
"\n"
"#canvas_text {\n"
"    position: absolute;\n"
"    z-index: 10;\n"
"    top: 12px;\n"
"}\n"
"\n"
"#container {\n"
"    min-width: 400px;\n"
"    width: 60%;\n"
"    height: 480px;\n"
"    display: block;\n"
"    margin: auto;\n"
"}\n"
"\n"
"#status { display: inline; color: #888; vertical-align: middle; }\n"
"#fps { display: inline; color: #888; vertical-align: middle; }\n"
"\n"
"#button_continue { float: right; }\n"
"select { width: 100px; }\n"
"input { width: 100px; vertical-align: middle; padding: 0; margin: 0; margin-left: 4px; margin-right: 4px; }\n"
".input_thing { border-radius: 2px; box-shadow: 0px 2px 2px #a7a7a7; background:#fff; max-width: 280px; padding: 6px; box-sizing: border-box; margin-bottom: 8px; }\n"
"\n"
"a { background: #bb5544; vertical-align: middle; padding: 2px 4px 2px 4px; border-radius: 2px; color: #fff; text-decoration: none; }\n"
"a:hover { background: #cc6655;}\n"
"a:active { background: #dd7766; }\n"
"</style>\n"
"<!-- STYLE END -->\n"
"\n"
"<!-- SHADERS BEGIN -->\n"
"<script id='shader_vs' type='notjs'>\n"
"    attribute vec4 coord;\n"
"    attribute vec4 color;\n"
"    attribute vec2 texel;\n"
"    varying vec4 v_color;\n"
"    varying vec2 v_texel;\n"
"    void main()\n"
"    {\n"
"        v_color = color;\n"
"        v_texel = texel;\n"
"        gl_Position = coord;\n"
"    }\n"
"</script>\n"
"<script id='shader_fs' type='notjs'>\n"
"    precision mediump float;\n"
"    varying vec4 v_color;\n"
"    varying vec2 v_texel;\n"
"    uniform sampler2D channel0;\n"
"    void main()\n"
"    {\n"
"        gl_FragColor = v_color*texture2D(channel0, v_texel);\n"
"    }\n"
"</script>\n"
"<!-- SHADERS END -->\n"
"\n"
"<!-- SCRIPT BEGIN -->\n"
"<script>\n"
"var ws = null;\n"
"var has_connection = false;\n"
"var cmd_data = null;\n"
"\n"
"var ctx_text = null;\n"
"var cvs_text = null;\n"
"\n"
"var cvs = null;\n"
"var gl = null;\n"
"\n"
"var program = null;\n"
"var loc_coord = null;\n"
"var loc_color = null;\n"
"var loc_texel = null;\n"
"var loc_chan0 = null;\n"
"\n"
"var vbo_user_coord = null;\n"
"var vbo_user_color = null;\n"
"var vbo_user_texel = null;\n"
"var vbo_quad_coord = null;\n"
"var vbo_quad_color = null;\n"
"var vbo_quad_texel = null;\n"
"\n"
"var tex_white = null;\n"
"var tex_view0 = null;\n"
"\n"
"var tex_view0_active = false;\n"
"var tex_view0_width = 0;\n"
"var tex_view0_height = 0;\n"
"\n"
"var vdb_max_variables = 1024;\n"
"var vdb_variables_label = new Array(vdb_max_variables);\n"
"var vdb_variables_value = new Array(vdb_max_variables);\n"
"var vdb_variables_valid = new Array(vdb_max_variables);\n"
"var vdb_variables_min   = new Array(vdb_max_variables);\n"
"var vdb_variables_max   = new Array(vdb_max_variables);\n"
"var vdb_variables_step  = new Array(vdb_max_variables);\n"
"var vdb_variables_used = 0;\n"
"\n"
"// User interface\n"
"var connection_address = window.location.host;\n"
"// var connection_address = 'localhost:8000';\n"
"var html_connection_address = null;\n"
"var html_status = null;\n"
"var html_button_connect = null;\n"
"// var html_fps = null;\n"
"\n"
"function clamp(v, lo, hi)\n"
"{\n"
"    if (v < lo) return lo;\n"
"    if (v > hi) return hi;\n"
"    return v;\n"
"}\n"
"\n"
"function parseStyle(style, alpha_value)\n"
"{\n"
"    var opacity = (style >> 7) & 0x01;\n"
"    var mode    = (style >> 6) & 0x01;\n"
"    var value   = (style >> 0) & 0x3F;\n"
"\n"
"    var r = 0;\n"
"    var g = 0;\n"
"    var b = 0;\n"
"    var a = 0;\n"
"    if (mode == 0) // set-color mode\n"
"    {\n"
"        var colors = [0x9E0142FF,0xEA2E49FF,0xFF6138FF,\n"
"                      0x527A24FF,0x60BE4EFF,0x75E65EFF,\n"
"                      0x225378FF,0x2186D4FF,0x35B1FFFF,\n"
"                      0x000000FF,0x1E2936FF,0x4A697DFF,\n"
"                      0xFFE0B8FF,0xFFF0D5FF,0xFFFFFFFF];\n"
"        rgba = colors[value % colors.length];\n"
"        r = rgba >> 24;\n"
"        g = rgba >> 16;\n"
"        b = rgba >> 8;\n"
"    }\n"
"    else if (mode == 1) // ramp-color mode\n"
"    {\n"
"        var two_pi = 2.0*3.1415926;\n"
"        var t = clamp(value/63.0, 0,1);\n"
"        r = clamp((0.54 + 0.5*Math.sin(two_pi*(0.5*t + 0.70)))*255.0, 0, 255);\n"
"        g = clamp((0.55 + 0.5*Math.sin(two_pi*(0.5*t + 0.80)))*255.0, 0, 255);\n"
"        b = clamp((0.56 + 0.7*Math.sin(two_pi*(0.5*t + 0.88)))*255.0, 0, 255);\n"
"    }\n"
"\n"
"    if (opacity == 1)\n"
"        a = 255*alpha_value;\n"
"    else\n"
"        a = 255;\n"
"\n"
"    return [r,g,b,a];\n"
"}\n"
"\n"
"function emitPoint2(x,y, r,g,b,a, coords,colors, nice_points,point_radius)\n"
"{\n"
"    var rx = point_radius/(cvs.width/2.0);\n"
"    var ry = point_radius/(cvs.height/2.0);\n"
"\n"
"    if (nice_points)\n"
"    {\n"
"        var n = 32;\n"
"        for (var i = 0; i < n; i++)\n"
"        {\n"
"            var t1 = 2.0*3.1415926*i/n;\n"
"            var t2 = 2.0*3.1415926*(i+1)/n;\n"
"            var x1 = x;\n"
"            var y1 = y;\n"
"            var x2 = x1 + rx*Math.cos(t1);\n"
"            var y2 = y1 + ry*Math.sin(t1);\n"
"            var x3 = x1 + rx*Math.cos(t2);\n"
"            var y3 = y1 + ry*Math.sin(t2);\n"
"            coords.push(x1,y1, x2,y2, x3,y3);\n"
"            colors.push(r,g,b,a, r,g,b,a, r,g,b,a);\n"
"        }\n"
"        return n*3;\n"
"    }\n"
"    else\n"
"    {\n"
"        var x1 = x-rx;\n"
"        var x2 = x+rx;\n"
"        var y1 = y-ry;\n"
"        var y2 = y+ry;\n"
"        coords.push(x1,y1, x2,y1, x2,y2, x2,y2, x1,y2, x1,y1);\n"
"        colors.push(r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a);\n"
"        return 6;\n"
"    }\n"
"}\n"
"\n"
"function emitLine2(x1,y1,x2,y2, r,g,b,a, coords,colors, line_width)\n"
"{\n"
"    var ln = Math.sqrt((x2-x1)*(x2-x1) + (y2-y1)*(y2-y1));\n"
"    var nx = -(y2-y1) / ln;\n"
"    var ny = (x2-x1) / ln;\n"
"\n"
"    var rx = (line_width/2.0)/(cvs.width/2.0);\n"
"    var ry = (line_width/2.0)/(cvs.height/2.0);\n"
"    var x11 = x1 - nx*rx;\n"
"    var y11 = y1 - ny*ry;\n"
"    var x21 = x2 - nx*rx;\n"
"    var y21 = y2 - ny*ry;\n"
"    var x12 = x1 + nx*rx;\n"
"    var y12 = y1 + ny*ry;\n"
"    var x22 = x2 + nx*rx;\n"
"    var y22 = y2 + ny*ry;\n"
"\n"
"    coords.push(x11,y11, x21,y21, x22,y22, x22,y22, x12,y12, x11,y11);\n"
"    colors.push(r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a);\n"
"\n"
"    return 6;\n"
"}\n"
"\n"
"function emitFillRect(x1,y1,x2,y2, r,g,b,a, coords,colors)\n"
"{\n"
"    coords.push(x1,y1, x2,y1, x2,y2, x2,y2, x1,y2, x1,y1);\n"
"    colors.push(r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a, r,g,b,a);\n"
"    return 6;\n"
"}\n"
"\n"
"function emitCircle(x,y,rx,ry, r,g,b,a, coords,colors)\n"
"{\n"
"    var n = 32;\n"
"    for (var i = 0; i < n; i++)\n"
"    {\n"
"        var t1 = 2.0*3.1415926*i/n;\n"
"        var t2 = 2.0*3.1415926*(i+1)/n;\n"
"        var x1 = x;\n"
"        var y1 = y;\n"
"        var x2 = x1 + rx*Math.cos(t1);\n"
"        var y2 = y1 + ry*Math.sin(t1);\n"
"        var x3 = x1 + rx*Math.cos(t2);\n"
"        var y3 = y1 + ry*Math.sin(t2);\n"
"        coords.push(x1,y1, x2,y2, x3,y3);\n"
"        colors.push(r,g,b,a, r,g,b,a, r,g,b,a);\n"
"    }\n"
"    return n*3;\n"
"}\n"
"\n"
"function addUserVariable(label, value, min, max, step)\n"
"{\n"
"    var registered_i = -1;\n"
"    for (var i = 0; i < vdb_variables_used; i++)\n"
"    {\n"
"        if (vdb_variables_label[i] === label)\n"
"        {\n"
"            registered_i = i;\n"
"            break;\n"
"        }\n"
"    }\n"
"\n"
"    if (registered_i < 0 && vdb_variables_used < vdb_max_variables)\n"
"    {\n"
"        registered_i = vdb_variables_used;\n"
"        vdb_variables_label[registered_i] = label;\n"
"        vdb_variables_value[registered_i] = value;\n"
"        vdb_variables_used++;\n"
"        htmlAddUserInput(label, min, max, step, value);\n"
"        console.log('Registered ' + label + ' with initial value ' + value);\n"
"    }\n"
"\n"
"    vdb_variables_valid[registered_i] = true;\n"
"    vdb_variables_min[registered_i] = min;\n"
"    vdb_variables_max[registered_i] = max;\n"
"    vdb_variables_step[registered_i] = step;\n"
"}\n"
"\n"
"function parseCommands(commands)\n"
"{\n"
"    tex_view0_active = false;\n"
"    for (var i = 0; i < vdb_variables_used; i++)\n"
"        vdb_variables_valid[i] = false;\n"
"\n"
"    var coords = [];\n"
"    var colors = [];\n"
"    var count = 0;\n"
"\n"
"    var little_endian = true;\n"
"    var view = new DataView(commands);\n"
"    var offset = 0;\n"
"\n"
"    var point_size = view.getFloat32(offset, little_endian); offset += 4;\n"
"    var line_size = view.getFloat32(offset, little_endian); offset += 4;\n"
"    var alpha_value = view.getFloat32(offset, little_endian); offset += 4;\n"
"    var nice_points = view.getUint8(offset, little_endian); offset += 1;\n"
"\n"
"    while (offset < view.byteLength)\n"
"    {\n"
"        var mode = view.getUint8(offset, little_endian); offset += 1;\n"
"        var style = view.getUint8(offset, little_endian); offset += 1;\n"
"        var rgba = parseStyle(style, alpha_value);\n"
"        var r = rgba[0];\n"
"        var g = rgba[1];\n"
"        var b = rgba[2];\n"
"        var a = rgba[3];\n"
"\n"
"        if (mode == 1) // point2\n"
"        {\n"
"            var x = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y = view.getFloat32(offset, little_endian); offset += 4;\n"
"            count += emitPoint2(x,y, r,g,b,a, coords,colors, nice_points,point_size);\n"
"        }\n"
"        else if (mode == 2) // point3\n"
"        {\n"
"            var x_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var z_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"        }\n"
"        else if (mode == 3) // line2\n"
"        {\n"
"            var x1 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y1 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var x2 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y2 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            count += emitLine2(x1,y1,x2,y2, r,g,b,a, coords,colors, line_size);\n"
"        }\n"
"        else if (mode == 4) // line3\n"
"        {\n"
"            var x1_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y1_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var z1_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var x2_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y2_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var z2_ndc = view.getFloat32(offset, little_endian); offset += 4;\n"
"        }\n"
"        else if (mode == 5) // fillRect\n"
"        {\n"
"            var x1 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y1 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var x2 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y2 = view.getFloat32(offset, little_endian); offset += 4;\n"
"            count += emitFillRect(x1,y1,x2,y2, r,g,b,a, coords,colors);\n"
"        }\n"
"        else if (mode == 6) // circle\n"
"        {\n"
"            var x = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var y = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var rx = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var ry = view.getFloat32(offset, little_endian); offset += 4;\n"
"            count += emitCircle(x,y,rx,ry, r,g,b,a, coords,colors);\n"
"        }\n"
"        else if (mode == 7) // image_rgb8\n"
"        {\n"
"            var width = view.getUint32(offset, little_endian); offset += 4;\n"
"            var height = view.getUint32(offset, little_endian); offset += 4;\n"
"            var size = width*height*3;\n"
"\n"
"            var data = new Uint8Array(commands, offset, size);\n"
"            offset += size;\n"
"\n"
"            if (tex_view0_width != width || tex_view0_height != height)\n"
"            // if (1) // @ texture upload optimization\n"
"            {\n"
"                tex_view0_width = width;\n"
"                tex_view0_height = height;\n"
"                gl.bindTexture(gl.TEXTURE_2D, tex_view0);\n"
"                gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, width, height, 0, gl.RGB, gl.UNSIGNED_BYTE, data);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);\n"
"                gl.bindTexture(gl.TEXTURE_2D, null);\n"
"            }\n"
"            else\n"
"            {\n"
"                gl.bindTexture(gl.TEXTURE_2D, tex_view0);\n"
"                gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RGB, gl.UNSIGNED_BYTE, data);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);\n"
"                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);\n"
"                gl.bindTexture(gl.TEXTURE_2D, null);\n"
"            }\n"
"            tex_view0_active = true;\n"
"            data = null;\n"
"        }\n"
"        else if (mode == 254) // slider (both int and float)\n"
"        {\n"
"            var label = new Uint8Array(commands, offset, 16); offset += 16;\n"
"            var value = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var min   = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var max   = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var step  = view.getFloat32(offset, little_endian); offset += 4;\n"
"            var string = String.fromCharCode.apply(null, label);\n"
"            addUserVariable(string, value, min, max, step);\n"
"        }\n"
"    }\n"
"\n"
"    gl.bindBuffer(gl.ARRAY_BUFFER, vbo_user_coord);\n"
"    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(coords), gl.DYNAMIC_DRAW);\n"
"\n"
"    gl.bindBuffer(gl.ARRAY_BUFFER, vbo_user_color);\n"
"    gl.bufferData(gl.ARRAY_BUFFER, new Uint8Array(colors), gl.DYNAMIC_DRAW);\n"
"\n"
"    for (var i = 0; i < vdb_variables_used; i++)\n"
"    {\n"
"        if (!vdb_variables_valid[i])\n"
"        {\n"
"            console.log('Removing ' + vdb_variables_label[i]);\n"
"            htmlRemoveUserInput(vdb_variables_label[i]);\n"
"\n"
"            // remove by swapping last element into i and decrementing count\n"
"            vdb_variables_label[i] = vdb_variables_label[vdb_variables_used-1];\n"
"            vdb_variables_value[i] = vdb_variables_value[vdb_variables_used-1];\n"
"            vdb_variables_valid[i] = vdb_variables_valid[vdb_variables_used-1];\n"
"            vdb_variables_min[i]   = vdb_variables_min[vdb_variables_used-1];\n"
"            vdb_variables_max[i]   = vdb_variables_max[vdb_variables_used-1];\n"
"            vdb_variables_step[i]  = vdb_variables_step[vdb_variables_used-1];\n"
"            vdb_variables_used--;\n"
"            i--;\n"
"        }\n"
"    }\n"
"\n"
"    coords = null;\n"
"    colors = null;\n"
"    view = null;\n"
"\n"
"    return count;\n"
"}\n"
"\n"
"function draw()\n"
"{\n"
"    // Resize framebuffer resolution to match size of displayed window\n"
"    if (cvs.width  != cvs.clientWidth || cvs.height != cvs.clientHeight)\n"
"    {\n"
"        cvs.width  = cvs.clientWidth;\n"
"        cvs.height = cvs.clientHeight;\n"
"    }\n"
"\n"
"    var num_elements = 0;\n"
"    if (cmd_data != null)\n"
"        num_elements = parseCommands(cmd_data);\n"
"\n"
"    gl.enable(gl.BLEND);\n"
"    gl.blendEquation(gl.FUNC_ADD);\n"
"    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);\n"
"\n"
"    gl.viewport(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight);\n"
"    gl.clearColor(0, 0, 0, 1);\n"
"    gl.clear(gl.COLOR_BUFFER_BIT);\n"
"    gl.useProgram(program);\n"
"\n"
"    // Draw background texture (if any)\n"
"    if (tex_view0_active)\n"
"    {\n"
"        gl.activeTexture(gl.TEXTURE0 + 0);\n"
"        gl.bindTexture(gl.TEXTURE_2D, tex_view0);\n"
"        gl.enableVertexAttribArray(loc_coord);\n"
"        gl.enableVertexAttribArray(loc_color);\n"
"        gl.enableVertexAttribArray(loc_texel);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_coord);\n"
"        gl.vertexAttribPointer(loc_coord, 2, gl.FLOAT, false, 0, 0);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_color);\n"
"        gl.vertexAttribPointer(loc_color, 4, gl.UNSIGNED_BYTE, true, 0, 0);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_texel);\n"
"        gl.vertexAttribPointer(loc_texel, 2, gl.FLOAT, false, 0, 0);\n"
"        gl.uniform1i(loc_chan0, 0);\n"
"        gl.drawArrays(gl.TRIANGLES, 0, 6);\n"
"        gl.bindTexture(gl.TEXTURE_2D, null);\n"
"    }\n"
"\n"
"    // Draw user geometry\n"
"    if (num_elements > 0)\n"
"    {\n"
"        gl.activeTexture(gl.TEXTURE0 + 0);\n"
"        gl.bindTexture(gl.TEXTURE_2D, tex_white);\n"
"        gl.enableVertexAttribArray(loc_coord);\n"
"        gl.enableVertexAttribArray(loc_color);\n"
"        gl.disableVertexAttribArray(loc_texel);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_user_coord);\n"
"        gl.vertexAttribPointer(loc_coord, 2, gl.FLOAT, false, 0, 0);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_user_color);\n"
"        gl.vertexAttribPointer(loc_color, 4, gl.UNSIGNED_BYTE, true, 0, 0);\n"
"        gl.uniform1i(loc_chan0, 0);\n"
"        gl.drawArrays(gl.TRIANGLES, 0, num_elements);\n"
"        gl.bindTexture(gl.TEXTURE_2D, null);\n"
"    }\n"
"}\n"
"\n"
"var connect_called = false;\n"
"\n"
"function connect()\n"
"{\n"
"    if (connect_called)\n"
"        return;\n"
"\n"
"    connect_called = true;\n"
"\n"
"    connection_address = html_connection_address.value;\n"
"    html_connection_address.hidden = true;\n"
"    html_button_connect.hidden = true;\n"
"    html_status.hidden = false;\n"
"\n"
"    setInterval(function()\n"
"    {\n"
"        if (!ws)\n"
"        {\n"
"            html_status.innerHTML = 'Connecting to ' + connection_address + '...';\n"
"\n"
"            ws = new WebSocket('ws://' + connection_address);\n"
"            ws.binaryType = 'arraybuffer';\n"
"\n"
"            ws.onopen = function()\n"
"            {\n"
"                html_status.innerHTML = 'Connected to ' + connection_address;\n"
"                ws.send('Hello from browser!');\n"
"                has_connection = true;\n"
"            }\n"
"\n"
"            ws.onclose = function()\n"
"            {\n"
"                tex_view0_active = false;\n"
"                cmd_data = null;\n"
"                ws = null;\n"
"                has_connection = false;\n"
"\n"
"                for (var i = 0; i < vdb_variables_used; i++)\n"
"                {\n"
"                    htmlRemoveUserInput(vdb_variables_label[i]);\n"
"                }\n"
"                vdb_variables_used = 0;\n"
"            }\n"
"\n"
"            ws.onmessage = function(e)\n"
"            {\n"
"                stats_bps_sum += e.data.byteLength;\n"
"                if (stats_bps_dt > 1.0)\n"
"                {\n"
"                    stats_bps = stats_bps_sum / stats_bps_dt;\n"
"                    stats_bps_sum = 0.0;\n"
"                    stats_bps_dt = 0.0;\n"
"                }\n"
"                var mbps = (10.0*stats_bps/(1024.0*1024.0)).toPrecision(2);\n"
"                html_status.innerHTML = 'Connected to ' + connection_address + ' (' + mbps + ' mbps)';\n"
"                cmd_data = e.data;\n"
"            }\n"
"        }\n"
"    }, 250);\n"
"}\n"
"\n"
"var animation_frame_t_first = null;\n"
"var animation_frame_t_prev = null;\n"
"var stats_bps_sum = 0;\n"
"var stats_bps_dt = 0;\n"
"var stats_bps = 0;\n"
"function anim(t)\n"
"{\n"
"    var delta = 1.0/60.0;\n"
"    var elapsed = 0.0;\n"
"    if (t)\n"
"    {\n"
"        if (!animation_frame_t_first) animation_frame_t_first = t;\n"
"        if (!animation_frame_t_prev) animation_frame_t_prev = t;\n"
"        delta = (t - animation_frame_t_prev)/1000.0;\n"
"        elapsed = (t - animation_frame_t_first)/1000.0;\n"
"        animation_frame_t_prev = t;\n"
"    }\n"
"\n"
"    if (has_connection)\n"
"    {\n"
"        draw();\n"
"\n"
"        // Draw 2D text\n"
"        // {\n"
"        //     if (cvs_text.width  != cvs.clientWidth || cvs_text.height != cvs.clientHeight)\n"
"        //     {\n"
"        //         cvs_text.width  = cvs.clientWidth;\n"
"        //         cvs_text.height = cvs.clientHeight;\n"
"        //     }\n"
"\n"
"        //     ctx_text.font = '14px Times';\n"
"        //     ctx_text.clearRect(0, 0, ctx_text.canvas.width, ctx_text.canvas.height);\n"
"        //     var s = 'FPS: ' + (1.0/delta).toPrecision(4);\n"
"        //     ctx_text.fillStyle = 'white';\n"
"        //     ctx_text.fillText(s, 0.0, 16.0);\n"
"        // }\n"
"\n"
"        stats_bps_dt += delta;\n"
"\n"
"        for (var i = 0; i < vdb_variables_used; i++)\n"
"        {\n"
"            var label = vdb_variables_label[i];\n"
"            var min = vdb_variables_min[i];\n"
"            var max = vdb_variables_max[i];\n"
"            var step = vdb_variables_step[i];\n"
"            vdb_variables_value[i] = clamp(vdb_variables_value[i], min, max);\n"
"            var value = vdb_variables_value[i];\n"
"        }\n"
"\n"
"        status = 's';\n"
"        status = status + ' ' + vdb_variables_used;\n"
"        for (var i = 0; i < vdb_variables_used; i++)\n"
"        {\n"
"            var label = vdb_variables_label[i];\n"
"            var value = vdb_variables_value[i];\n"
"            status = status + ' ' + label + ' ' + value;\n"
"        }\n"
"        try {\n"
"            ws.send(status);\n"
"        } catch (error) {\n"
"            console.log(error);\n"
"        }\n"
"    }\n"
"\n"
"    requestAnimationFrame(anim);\n"
"}\n"
"\n"
"function createShader(gl, type, source)\n"
"{\n"
"    var shader = gl.createShader(type);\n"
"    gl.shaderSource(shader, source);\n"
"    gl.compileShader(shader);\n"
"    var success = gl.getShaderParameter(shader, gl.COMPILE_STATUS);\n"
"    if (success)\n"
"        return shader;\n"
"    console.log(gl.getShaderInfoLog(shader));\n"
"    gl.deleteShader(shader);\n"
"}\n"
"\n"
"function createProgram(gl, vs, fs)\n"
"{\n"
"    var program = gl.createProgram();\n"
"    gl.attachShader(program, vs);\n"
"    gl.attachShader(program, fs);\n"
"    gl.linkProgram(program);\n"
"    var success = gl.getProgramParameter(program, gl.LINK_STATUS);\n"
"    if (success)\n"
"        return program;\n"
"    console.log(gl.getProgramInfoLog(program));\n"
"    gl.deleteProgram(program);\n"
"}\n"
"\n"
"function init()\n"
"{\n"
"    // Compile the ubershader\n"
"    var shader_vs_src = document.getElementById('shader_vs').text;\n"
"    var shader_fs_src = document.getElementById('shader_fs').text;\n"
"    var shader_vs = createShader(gl, gl.VERTEX_SHADER, shader_vs_src);\n"
"    var shader_fs = createShader(gl, gl.FRAGMENT_SHADER, shader_fs_src);\n"
"    program = createProgram(gl, shader_vs, shader_fs);\n"
"\n"
"    // Get attribute locations\n"
"    loc_coord = gl.getAttribLocation(program, 'coord');\n"
"    loc_color = gl.getAttribLocation(program, 'color');\n"
"    loc_texel = gl.getAttribLocation(program, 'texel');\n"
"    loc_chan0 = gl.getUniformLocation(program, 'chan0');\n"
"\n"
"    // These vertex buffers are updated in generateTriangles\n"
"    vbo_user_coord = gl.createBuffer();\n"
"    vbo_user_color = gl.createBuffer();\n"
"    vbo_user_texel = gl.createBuffer();\n"
"\n"
"    // These vertex buffers are used to draw background textures\n"
"    vbo_quad_coord = gl.createBuffer();\n"
"    vbo_quad_color = gl.createBuffer();\n"
"    vbo_quad_texel = gl.createBuffer();\n"
"    {\n"
"        var coords = [ -1,-1, +1,-1, +1,+1, +1,+1, -1,+1, -1,-1 ];\n"
"        var texels = [ 0,0, 1,0, 1,1, 1,1, 0,1, 0,0 ];\n"
"        var colors = [ 255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255 ];\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_coord); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(coords), gl.STATIC_DRAW);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_color); gl.bufferData(gl.ARRAY_BUFFER, new   Uint8Array(colors), gl.STATIC_DRAW);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, vbo_quad_texel); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(texels), gl.STATIC_DRAW);\n"
"        gl.bindBuffer(gl.ARRAY_BUFFER, null);\n"
"    }\n"
"\n"
"    // This texture is for drawing non-textured geometry\n"
"    tex_white = gl.createTexture();\n"
"    {\n"
"        var data = new Uint8Array([255,255,255,255]);\n"
"        gl.bindTexture(gl.TEXTURE_2D, tex_white);\n"
"        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, data);\n"
"        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);\n"
"        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);\n"
"        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);\n"
"        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);\n"
"        gl.bindTexture(gl.TEXTURE_2D, null);\n"
"    }\n"
"\n"
"    // These textures can be assigned data by the user (from generateTriangles)\n"
"    tex_view0 = gl.createTexture();\n"
"    tex_view0_active = false;\n"
"}\n"
"\n"
"// Adds the following to the user widget section\n"
"// div: id = label\n"
"//   input: id = label + '_input'\n"
"//   label: id = label + '_label'\n"
"function htmlAddUserInput(label, min, max, step, value)\n"
"{\n"
"    var div = document.createElement('div');\n"
"    div.className = 'input_thing';\n"
"    div.id = label + '_div';\n"
"\n"
"    // create input\n"
"    {\n"
"        var e = document.createElement('input');\n"
"        e.id = label;\n"
"        e.setAttribute('type', 'range');\n"
"        e.setAttribute('min', min);\n"
"        e.setAttribute('max', max);\n"
"        e.setAttribute('step', step);\n"
"        e.setAttribute('value', value);\n"
"        e.setAttribute('onchange', 'sliderChanged(this)')\n"
"        e.setAttribute('oninput', 'sliderChanged(this)')\n"
"        div.appendChild(e);\n"
"    }\n"
"\n"
"    // create label text\n"
"    {\n"
"        var e = document.createElement('label');\n"
"        e.id = label + '_label';\n"
"        if (parseInt(step) == step)\n"
"            e.innerHTML = label + ' = ' + value;\n"
"        else\n"
"            e.innerHTML = label + ' = ' + value.toPrecision(3);\n"
"        div.appendChild(e);\n"
"    }\n"
"\n"
"    var user = document.getElementById('user_widgets');\n"
"    user.appendChild(div);\n"
"}\n"
"\n"
"function htmlRemoveUserInput(label)\n"
"{\n"
"    var user = document.getElementById('user_widgets');\n"
"    var item = document.getElementById(label + '_div');\n"
"    user.removeChild(item);\n"
"}\n"
"\n"
"function pageload()\n"
"{\n"
"    if (!('WebSocket' in window))\n"
"    {\n"
"        alert('Your browser does not support WebSockets! Sorry, good luck!');\n"
"        return;\n"
"    }\n"
"\n"
"    cvs = document.getElementById('canvas');\n"
"    gl = cvs.getContext('webgl');\n"
"    if (!gl)\n"
"    {\n"
"        alert('Your browser does not support WebGL! Sorry, good luck!');\n"
"        return;\n"
"    }\n"
"\n"
"    cvs_text = document.getElementById('canvas_text');\n"
"    ctx_text = cvs_text.getContext('2d');\n"
"\n"
"    html_connection_address = document.getElementById('connection_address');\n"
"    html_status = document.getElementById('status');\n"
"    html_button_connect = document.getElementById('button_connect');\n"
"\n"
"    html_connection_address.value = connection_address;\n"
"    html_status.hidden = true;\n"
"\n"
"    connect();\n"
"    init();\n"
"    anim();\n"
"\n"
"    cvs.addEventListener('click', canvasClick);\n"
"    cvs.addEventListener('mousemove', canvasMouseMove);\n"
"}\n"
"\n"
"function canvasMouseMove(e)\n"
"{\n"
"    // console.log(e.clientX + ' ' + e.clientY);\n"
"}\n"
"\n"
"function canvasClick(e)\n"
"{\n"
"    if (ws != null)\n"
"    {\n"
"        var x = -1.0 + 2.0*e.offsetX/cvs.clientWidth;\n"
"        var y = +1.0 - 2.0*e.offsetY/cvs.clientHeight;\n"
"        ws.send('m ' + x + ' ' + y);\n"
"    }\n"
"}\n"
"\n"
"function sliderChanged(e)\n"
"{\n"
"    for (var i = 0; i < vdb_variables_used; i++)\n"
"    {\n"
"        if (e.id === vdb_variables_label[i])\n"
"        {\n"
"            var v = parseFloat(e.value);\n"
"            vdb_variables_value[i] = v;\n"
"            e.setAttribute('min', vdb_variables_min[i]);\n"
"            e.setAttribute('max', vdb_variables_max[i]);\n"
"            e.setAttribute('step', vdb_variables_step[i]);\n"
"            if (parseInt(vdb_variables_step[i]) == vdb_variables_step[i])\n"
"                document.getElementById(e.id + '_label').innerHTML = e.id + ' = ' + v;\n"
"            else\n"
"                document.getElementById(e.id + '_label').innerHTML = e.id + ' = ' + v.toPrecision(3);\n"
"        }\n"
"    }\n"
"}\n"
"\n"
"function buttonConnect()\n"
"{\n"
"    connect();\n"
"}\n"
"\n"
"function buttonContinue()\n"
"{\n"
"    if (ws != null)\n"
"        ws.send('c');\n"
"}\n"
"</script>\n"
"<!-- SCRIPT END-->\n"
"\n"
"<!-- HTML BEGIN -->\n"
"</head>\n"
"<body onload='pageload()'>\n"
"    <div id='container'>\n"
"        <canvas id='canvas'></canvas>\n"
"        <canvas id='canvas_text'></canvas>\n"
"\n"
"        <a id='button_continue' href='javascript:buttonContinue()'>Continue</a>\n"
"\n"
"        <div class='input_thing'>\n"
"            <input id='connection_address' type='text'/>\n"
"            <a id='button_connect' href='javascript:buttonConnect()'>Connect</a>\n"
"            <p id='status'></p>\n"
"        </div>\n"
"\n"
"        <div id='user_widgets'>\n"
"        </div>\n"
"    </div>\n"
"</body>\n"
"</html>\n"
"<!-- HTML END -->\n"
;
// End embedded app.html
