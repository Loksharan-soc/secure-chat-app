#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <openssl/kdf.h>
#include <string.h>
#include <openssl/aes.h>

#include <string.h>  // For memcpy
#include <openssl/rand.h>
#include <openssl/err.h>


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

#define KEY_LENGTH 320   // Length of the derived key (in bytes)
#define IV_LENGTH 160    // Length of the IV (in bytes)
#define AES_KEY_LENGTH 32 // 256 bits
#define AES_BLOCK_SIZE 16  // 128 bits

// Public/global variables
unsigned char derivedKey[KEY_LENGTH];
unsigned char iv[IV_LENGTH];
mpz_t sharedSecret; 


/*int deriveAESKey(const mpz_t shared_secret, unsigned char *key, unsigned char *iv) {
    // Derive the AES key from the shared secret (use a KDF in production)
    unsigned char secret_bytes[32222]; // Adjust size as needed
    mpz_export(secret_bytes, NULL, 1, sizeof(secret_bytes[0]), 0, 0, shared_secret);

    // Use the first 32 bytes for AES key
    memcpy(key, secret_bytes, AES_KEY_LENGTH);
    
    // Generate a random IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        return -1; // Error generating IV
    }
    return 0;
}*/

// Function to derive key and IV

#define SALT_LENGTH 16
#define ITERATIONS 10000
#define AES_KEY_LENGTH 32 // 256 bits for AES-256
#define AES_BLOCK_SIZE 16  // 128 bits for AES


int deriveAESKey(const mpz_t shared_secret, unsigned char *key, unsigned char *iv) {
    // Derive the AES key from the shared secret (use a KDF in production)
    unsigned char secret_bytes[32222]; // Adjust size as needed
    mpz_export(secret_bytes, NULL, 1, sizeof(secret_bytes[0]), 0, 0, shared_secret);

    // Use the first 32 bytes for AES key
    memcpy(key, secret_bytes, AES_KEY_LENGTH);
    
    // Generate a random IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        return -1; // Error generating IV
    }

	//printf("\nold nf%s\n",derivedKey);
    return 0;
}
/*void testKeyDerivation(unsigned char *derivedKey, size_t keyLength) {
    // Example plaintext
    unsigned char plaintext[] = "Hello, World!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int outlen, tmplen;
    EVP_CIPHER_CTX *ctx;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();

    // Encrypt
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, derivedKey, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, strlen((const char *)plaintext));
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    outlen += tmplen;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();

    // Decrypt
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, derivedKey, NULL);
    EVP_DecryptUpdate(ctx, decryptedtext, &outlen, ciphertext, outlen);
    EVP_DecryptFinal_ex(ctx, decryptedtext + outlen, &tmplen);
    outlen += tmplen;

    // Null-terminate decrypted text
    decryptedtext[outlen] = '\0';

    // Check if decryption matches the original plaintext
    if (strcmp((const char *)plaintext, (const char *)decryptedtext) == 0) {
        printf("Key is valid! Decrypted text matches original.\n");
    } else {
        printf("Key is invalid! Decrypted text does not match.\n");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}*/
void mpz_to_bytes(unsigned char *bytes, mpz_t value) {
    size_t size = mpz_sizeinbase(value, 2) / 8 + 1; // Number of bytes needed
    memset(bytes, 0, 12880); // Clear the byte array
    mpz_export(bytes + (12880 - size), NULL, 1, 1, 0, 0, value); // Store in big-endian format
}
void bytes_to_mpz(const unsigned char *bytes, size_t size, mpz_t value) {
    mpz_import(value, size, 1, 1, 0, 0, bytes + (12880 - size)); // Import from big-endian format
}
void performHandshake(int sockfd) {
    mpz_t localSecret, localPublic, remotePublic;
    unsigned char localPublicBytes[12880]; // Adjust size as needed
    unsigned char remotePublicBytes[12880]; // Adjust size as needed

    // Initialize mpz_t variables
    mpz_init(localSecret);
    mpz_init(localPublic);
    mpz_init(remotePublic);
    mpz_init(sharedSecret);

    // Generate local key pair
    if (dhGen(localSecret, localPublic) != 0) {
        fprintf(stderr, "Failed to generate local key\n");
        goto cleanup;
    }

    // Convert public key to bytes and send
    mpz_to_bytes(localPublicBytes, localPublic); // Corrected order of arguments
    ssize_t sentBytes = send(sockfd, localPublicBytes, sizeof(localPublicBytes), 0);
    if (sentBytes < 0) {
        perror("Failed to send local public key");
        goto cleanup;
    }

    // Receive remote public key bytes
    ssize_t receivedBytes = recv(sockfd, remotePublicBytes, sizeof(remotePublicBytes), 0);
    if (receivedBytes < 0) {
        perror("Failed to receive remote public key");
        goto cleanup;
    }

    // Convert received bytes back to mpz_t
    bytes_to_mpz(remotePublicBytes, sizeof(remotePublicBytes), remotePublic);

    // Compute shared secret: sharedSecret = remotePublic^localSecret mod p
    mpz_powm(sharedSecret, remotePublic, localSecret, p);

    // Print the shared secret (for debugging, remove in production)
    //gmp_printf("Shared secret: %Zd\n", sharedSecret);
    //deriveKey();

    printf("Handshake completed successfully\n");

	// printf("keyy %s \n",derivedKey);
	 deriveAESKey(  sharedSecret,   derivedKey,  iv);


//testKeyDerivation(derivedKey,32);

cleanup:
    // Clean up
    mpz_clear(localSecret);
    mpz_clear(localPublic);
    mpz_clear(remotePublic);
	mpz_clear(sharedSecret);
}
int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	performHandshake(sockfd);

	return 0;
}
static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
		performHandshake(sockfd);

	return 0;
}
static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}


/*static void sendMessage(GtkWidget* w , gpointer )
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; 
	GtkTextIter mend;   
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	ssize_t nbytes;
	if ((nbytes = send(sockfd,message,len,0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; 
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}*/







int encryptMessage(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[16];  // AES block size is 16 bytes

    // Generate a random IV (Initialization Vector)
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating IV\n");
        return -1;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating context\n");
        return -1;
    }

    // Initialize the encryption operation with AES-128-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        return -1;
    }

    // Provide the message to be encrypted, and obtain the ciphertext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error during encryption update\n");
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error during encryption finalization\n");
        return -1;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV to the ciphertext so it can be used for decryption
    memmove(ciphertext + sizeof(iv), ciphertext, ciphertext_len);
    memcpy(ciphertext, iv, sizeof(iv));  // IV at the beginning of the message
    ciphertext_len += sizeof(iv);

    return ciphertext_len;
}
int decryptMessage(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    unsigned char iv[16];  // AES block size is 16 bytes

    // Extract the IV from the beginning of the ciphertext
    if (ciphertext_len < sizeof(iv)) {
        fprintf(stderr, "Ciphertext too short to contain IV\n");
        return -1;
    }
    memcpy(iv, ciphertext, sizeof(iv));

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating context\n");
        return -1;
    }

    // Initialize the decryption operation with AES-128-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt the ciphertext (excluding the IV at the start)
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + sizeof(iv), ciphertext_len - sizeof(iv)) != 1) {
        fprintf(stderr, "Error during decryption update\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret <= 0) {
        fprintf(stderr, "Error during decryption finalization\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}




























static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
    char* tags[2] = {"self",NULL};
    tsappend("me: ", tags, 0);
    GtkTextIter mstart; /* start of message pointer */
    GtkTextIter mend;   /* end of message pointer */
    gtk_text_buffer_get_start_iter(mbuf, &mstart);
    gtk_text_buffer_get_end_iter(mbuf, &mend);
    char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);

    // Encrypt the message
    unsigned char ciphertext[128];  // Make sure this size is large enough
    int ciphertext_len = encryptMessage((unsigned char*)message, strlen(message), ciphertext, derivedKey);

    if (ciphertext_len < 0) {
        error("Encryption failed");
    }

    // Send the encrypted message
    ssize_t nbytes;
    if ((nbytes = send(sockfd, ciphertext, ciphertext_len, 0)) == -1) {
        error("send failed");
    }

    tsappend(message, NULL, 1);
    free(message);

    // Clear message text and reset focus
    gtk_text_buffer_delete(mbuf, &mstart, &mend);
    gtk_widget_grab_focus(w);
}
void* recvMsg(void*)
{
    size_t maxlen = 512;
    unsigned char ciphertext[maxlen];  // Buffer to receive encrypted messages
    unsigned char decryptedtext[128];  // Buffer for decrypted messages
    ssize_t nbytes;

    while (1) {
        // Receive the encrypted message
        if ((nbytes = recv(sockfd, ciphertext, maxlen, 0)) == -1) {
            error("recv failed");
        }
        if (nbytes == 0) {
            // Handle disconnection
            return 0;
        }

        // Decrypt the message
        int decrypted_len = decryptMessage(ciphertext, nbytes, decryptedtext, derivedKey);

        if (decrypted_len < 0) {
            error("Decryption failed");
        }

        // Null-terminate the decrypted message
        decryptedtext[decrypted_len] = '\0';

        // Display the decrypted message in the chat UI
        char* m = malloc(decrypted_len + 1);
        memcpy(m, decryptedtext, decrypted_len);
        m[decrypted_len] = '\0';  // Ensure null-terminated message
        g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
    }
    return 0;
}


















int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
		   // performHandshake(); // Call handshake for client

	} else {
		initServerNet(port);
		   // performHandshake(); // Call handshake for server

	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */


