#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "scryptn.h"
    #include "sha256d.h"
}


using namespace node;
using namespace v8;

#if NODE_MAJOR_VERSION >= 4

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)

#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)

#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));

#define RETURN_EXCEPT(msg) \
    do { \
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg))); \
        return; \
    } while (0)

#else

#define DECLARE_INIT(x) \
    void x(Handle<Object> exports)

#define DECLARE_FUNC(x) \
    Handle<Value> x(const Arguments& args)

#define DECLARE_SCOPE \
    HandleScope scope

#define SET_BUFFER_RETURN(x, len) \
    do { \
        Buffer* buff = Buffer::New(x, len); \
        return scope.Close(buff->handle_); \
    } while (0)

#define SET_BOOLEAN_RETURN(x) \
    return scope.Close(Boolean::New(x));

#define RETURN_EXCEPT(msg) \
    return ThrowException(Exception::Error(String::New(msg)))

#endif // NODE_MAJOR_VERSION

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> target = args[0]->ToObject(Nan::GetCurrentContext()).FromMaybe(v8::Local<v8::Object>()); \
 \
    if(!Buffer::HasInstance(target)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(target); \
    char output[32]; \
 \
    uint32_t input_len = Buffer::Length(target); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

 
 DECLARE_CALLBACK(sha256d, sha256d_hash, 32);


DECLARE_FUNC(scrypt) {
   DECLARE_SCOPE;

   if (args.Length() < 3)
       RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");

   Local<Object> target = args[0]->ToObject(Nan::GetCurrentContext()).FromMaybe(v8::Local<v8::Object>());

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nValue = args[1]->ToUint32(Nan::GetCurrentContext()).ToLocalChecked()->Value();
   unsigned int rValue = args[2]->ToUint32(Nan::GetCurrentContext()).ToLocalChecked()->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   SET_BUFFER_RETURN(output, 32);
}



DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "sha256d", sha256d);
    
}

NODE_MODULE(multihashing, init)
