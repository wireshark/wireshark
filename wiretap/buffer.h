/*
	buffer.h
	--------

*/

#define SOME_FUNCTIONS_ARE_DEFINES

typedef struct Buffer {

	char			*data;
	unsigned int	allocated;
	unsigned int	start;
	unsigned int	first_free;

} Buffer;

void buffer_init(Buffer* buffer, unsigned int space);
void buffer_free(Buffer* buffer);
void buffer_assure_space(Buffer* buffer, unsigned int space);
void buffer_append(Buffer* buffer, char *from, unsigned int bytes);
void buffer_remove_start(Buffer* buffer, unsigned int bytes);

#ifdef SOME_FUNCTIONS_ARE_DEFINES
 #define buffer_increase_length(buffer,bytes) (buffer)->first_free += (bytes)
 #define buffer_length(buffer) ((buffer)->first_free - (buffer)->start)
 #define buffer_start_ptr(buffer) ((buffer)->data + (buffer)->start)
 #define buffer_end_ptr(buffer) ((buffer)->data + (buffer)->first_free)
#else
 void buffer_increase_length(Buffer* buffer, unsigned int bytes);
 unsigned int buffer_length(Buffer* buffer);
 char* buffer_start_ptr(Buffer* buffer);
 char* buffer_end_ptr(Buffer* buffer);
#endif
