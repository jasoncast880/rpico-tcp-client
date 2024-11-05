#include <string.h>
#include <time.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#ifndef EC2_IP
#define EC2_IP "192.168.1.1"
#endif

#define TCP_PORT 4242
#define DEBUG_printf printf
#define BUF_SIZE 2048

//set this to 0 to disable printfs (more efficient for mcu)
#define DEBUG_PRINT_ENABLED 1

#define TEST_ITERATIONS 10
#define POLL_TIME_S 5

/*
 * This program conncts to WAP, then to an IP of an EC2 Server. 
 * It then reads the buffer on the EC2 Server
 * Afterwards it writes the data back to the server.
 * The data (2048 Byte buffer) is broken up in the network layer; ie the transport layer app(this app)
 * will send all aat one step/function call, but then the network decides how to segment the data through the network.
 * Expect that the data will come in 2 packets.
 */

#if 0
static void dump_bytes(const uint8_t *bptr, uint32_t len) {
    unsigned int i = 0;

    printf("dump_bytes %d", len);
    for (i = 0; i < len;) {
        if ((i & 0x0f) == 0) {
            printf("\n");
        } else if ((i & 0x07) == 0) {
            printf(" ");
        }
        printf("%02x ", bptr[i++]);
    }
    printf("\n");
}
#define DUMP_BYTES dump_bytes
#else
#define DUMP_BYTES(A,B)
#endif

typedef struct TCP_CLIENT_T_ { //super important
    struct tcp_pcb *tcp_pcb;
    ip_addr_t remote_addr;
    uint8_t buffer[BUF_SIZE];
    int buffer_len;
    int sent_len;
    bool complete;
    int run_count;
    bool connected;
} TCP_CLIENT_T;

static TCP_CLIENT_T* tcp_client_init() {
    TCP_CLIENT_T *state = calloc(1, sizeof(TCP_CLIENT_T));
    if(!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    ip4addr_aton(EC2_IP, &state->remote_addr);
    return state;
}

static err_t tcp_client_close(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    err_t err = ERR_OK;
    if(state->tcp_pcb!=NULL) {
        tcp_arg(state->tcp_pcb, NULL);
        tcp_poll(state->tcp_pcb, NULL, 0);
        tcp_sent(state->tcp_pcb, NULL);
        tcp_recv(state->tcp_pcb, NULL);
        tcp_err(state->tcp_pcb, NULL);
        err = tcp_close(state->tcp_pcb);
        if(err!=ERR_OK){
            DEBUG_printf("close failed %d, calling abort\n",err);
            tcp_abort(state->tcp_pcb);
            err = ERR_ABRT;
        }
        state->tcp_pcb = NULL;
    }
    return err;
}

static err_t tcp_result(void *arg, int status) { 
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if(status == 0) {
        DEBUG_printf("test success\n");
    } else {
        DEBUG_printf("test failed %d\n", status);
    }
    state->complete = true;
    return tcp_client_close(arg);
}

//
//no response is an error; poll is a keep-alive-connection function
static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_client_poll\n");
    return tcp_result(arg, -1); //no response is an error? ??
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if(err!=ERR_OK){
        printf("connect failed %d\n", err);
        return tcp_result(arg, err);
    }
    state->connected=true;
    DEBUG_printf("Waiting for buffer from server\n");
    return ERR_OK;
}

//increment/checking data packets
static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb,u16_t len){
   TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg; 
   DEBUG_printf("tcp_client_sent %u\n", len);
   state->sent_len += len;
   
   if(state->sent_len >= BUF_SIZE) {

       state->run_count++;
       if(state->run_count >= TEST_ITERATIONS) {
           tcp_result(arg, 0);
           return ERR_OK;
        }

       //receive new buffer from the server 
       state->buffer_len = 0;
       state->sent_len = 0;
       DEBUG_printf("waiting for buffer from the server \n");
   }
   return ERR_OK;
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if(!p){
        return tcp_result(arg,-1);
    }
    //pico examples explanation : picow_tcp_client line 140
    cyw43_arch_lwip_check();
    if(p->tot_len>0){
        DEBUG_printf("recv %d err %d\n", p->tot_len, err);
        for (struct pbuf *q = p; q!=NULL; q=q->next) {
            DUMP_BYTES(q->payload, q->len);
        }
        //receive the buffer
        const uint16_t buffer_left = BUF_SIZE - state->buffer_len;
        state->buffer_len += pbuf_copy_partial(p, 
                state->buffer + state->buffer_len,
                p->tot_len>buffer_left ? buffer_left : p->tot_len, 
                0);
        tcp_recved(tpcb, p->tot_len);
    }
    pbuf_free(p);

    if(state->buffer_len == BUF_SIZE) {
        DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t err = tcp_write(tpcb,
                state->buffer,
                state->buffer_len,
                TCP_WRITE_FLAG_COPY);
        if(err!=ERR_OK){
            DEBUG_printf("failed to write data");
            return tcp_result(arg,-1);
        }
    }
    return ERR_OK;
}

//you know what this does.
static void tcp_client_err(void *arg, err_t err){
   if(err!=ERR_ABRT){
        tcp_result(arg, err);
   }
}

// ==== implementation(s) are below: trying with pico_cyw4_arch_poll ======

static bool tcp_client_open(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("Connecting to %s port %u\n", ip4addr_ntoa(&state->remote_addr), TCP_PORT);
    state->tcp_pcb = tcp_new_ip_type(IP_GET_TYPE(&state->remote_addr));
    if(!state->tcp_pcb){
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    //see, all of the tcp_x functions use a callback api (other than tcp_x); lets me make my own client callback functions; in the event that i make a server, or i need to serve packets via tcp, i can use this module as a way to accomplish this.
    tcp_arg(state->tcp_pcb, state);
    tcp_poll(state->tcp_pcb, tcp_client_poll, POLL_TIME_S*2);
    tcp_sent(state->tcp_pcb, tcp_client_sent);
    tcp_recv(state->tcp_pcb, tcp_client_recv);
    tcp_err(state->tcp_pcb, tcp_client_err);

    state->buffer_len = 0;

    //cyw43_arch_lwip??  
    //cyw arch lwip appears to take up cpu cycles if the cyw arch isn't polling.
    //reference the pico_w example i guess
    cyw43_arch_lwip_begin();
    err_t err = tcp_connect(state->tcp_pcb, &state->remote_addr, TCP_PORT, tcp_client_connected);
    cyw43_arch_lwip_end();

    return err == ERR_OK;
}

void run_tcp_client_test(void) {
    TCP_CLIENT_T *state = tcp_client_init(); //implement
    if(!state){
        return;
    }
    if(!tcp_client_open(state)){
        tcp_result(state, -1);
        return;
    }
    while(!state->complete){
#if PICO_CYW43_ARCH_POLL
    cyw43_arch_poll();
    cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
#else //peepeepoopoo
    sleep_ms(1000);
#endif
    }
    free(state);
}

/* Things I Don't understand:
 * Keep-alive mode; what is?
 * how & when do i implement a threadsafe-background over full rtos integration
 */

int main() {
    stdio_init_all();

    if(cyw43_arch_init()) {
        //DEBUG_printf("failed to initalize\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();

    printf("Connecting to Wi-Fi... \n");
    if(cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, 
                WIFI_PASSWORD,
                CYW43_AUTH_WPA2_AES_PSK,
                100000)) {
        printf("failed to connect.\n");
        return 1;
    } else {
        printf("Connected.\n");
    }
    for(int n=0;n<10;n++){
        run_tcp_client_test(); 
    }
    printf("complete\n");
    cyw43_arch_deinit();
    return 0;
}
