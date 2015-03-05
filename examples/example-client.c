/* gcc example.c -o example $(pkg-config --cflags --libs libmongoc-1.0) */

/* ./example-client [CONNECTION_STRING [COLLECTION_NAME]] */

#include <mongoc.h>
#include <stdio.h>
#include <stdlib.h>

PCCERT_CONTEXT getServerCertificate()
{
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT aCertContext = NULL;

    //-------------------------------------------------------
    // Open the My store, also called the personal store.
    // This call to CertOpenStore opens the Local_Machine My 
    // store as opposed to the Current_User's My store.

    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (hMyCertStore == NULL)
    {
        printf("Error opening MY store for server.\n");
        goto cleanup;
    }
    //-------------------------------------------------------
    // Search for a certificate with some specified
    // string in it. This example attempts to find
    // a certificate with the string "example server" in
    // its subject string. Substitute an appropriate string
    // to find a certificate for a specific user.

    aCertContext = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        "markcb", // use appropriate subject name
        NULL
        );

    if (aCertContext == NULL)
    {
        printf("Error retrieving server certificate.");
        goto cleanup;
    }
cleanup:
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }
    return aCertContext;
}

int
main (int   argc,
      char *argv[])
{
   mongoc_client_t *client;
   mongoc_collection_t *collection;
   mongoc_cursor_t *cursor;
   bson_error_t error;
   const bson_t *doc;
   const char *uristr = "mongodb://127.0.0.1/?ssl=true&authMechanism=MONGODB-X509";
   const char *collection_name = "test";
   bson_t query;
   char *str;
   mongoc_ssl_opt_t ssl_opts = { 0 };

   mongoc_init ();

   if (argc > 1) {
      uristr = argv [1];
   }

   if (argc > 2) {
      collection_name = argv [2];
   }

   PCCERT_CONTEXT cert = getServerCertificate();
   ssl_opts.certificate = cert;
   ssl_opts.pem_file = "ac";
   ssl_opts.weak_cert_validation = false;

   client = mongoc_client_new (uristr);
   mongoc_client_set_ssl_opts(client, &ssl_opts);


   if (!client) {
      fprintf (stderr, "Failed to parse URI.\n");
      return EXIT_FAILURE;
   }

   bson_init (&query);

#if 0
   bson_append_utf8 (&query, "hello", -1, "world", -1);
#endif

   collection = mongoc_client_get_collection (client, "test", collection_name);
   cursor = mongoc_collection_find (collection,
                                    MONGOC_QUERY_NONE,
                                    0,
                                    0,
                                    0,
                                    &query,
                                    NULL,  /* Fields, NULL for all. */
                                    NULL); /* Read Prefs, NULL for default */

   while (mongoc_cursor_next (cursor, &doc)) {
      str = bson_as_json (doc, NULL);
      fprintf (stdout, "%s\n", str);
      bson_free (str);
   }

   if (mongoc_cursor_error (cursor, &error)) {
      fprintf (stderr, "Cursor Failure: %s\n", error.message);
      BSON_ASSERT(false);
      return EXIT_FAILURE;
   }

   bson_destroy (&query);
   mongoc_cursor_destroy (cursor);
   mongoc_collection_destroy (collection);
   mongoc_client_destroy (client);

   mongoc_cleanup ();

   return EXIT_SUCCESS;
}
