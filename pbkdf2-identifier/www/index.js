import * as pbkdf2_identifier from "pbkdf2-identifier";

function base64decode(enc_data) {
    let data = atob(enc_data)
    let buffer = new Uint8Array(new ArrayBuffer(data.length))

    for(let i = 0; i < data.length; i++) {
        buffer[i] = data.charCodeAt(i);
    }

    return buffer
}

let enc = new TextEncoder()
let password = enc.encode("hello")
let salt = base64decode("FOWB3L4YoTcaPvzxtP+j/A==")
let hash = base64decode("xrHVkBEQCyPCBcSzoQvMc0kOx8f51NKknd3dAQNeRZU=")
let alg = pbkdf2_identifier.HashPrimitive.HMACSHA512

alert("Iteration count: " + pbkdf2_identifier.identify_iterations(password, hash, salt, alg))

let return_value = pbkdf2_identifier.identify_all(password, hash, salt, 1000)
alert(pbkdf2_identifier.primitive_name(return_value.primitive) + ": " + return_value.iterations + " iterations")

return_value.free()