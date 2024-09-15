require 'openssl'

def generate_rsa_keys
  p = OpenSSL::BN.generate_prime(128).to_i
  q = OpenSSL::BN.generate_prime(128).to_i
  n = p * q
  phi = (p - 1) * (q - 1)

  e = 3
  e += 2 while e.gcd(phi) != 1

  d = e.mod_inverse(phi)
  
  public_key = [e, n]
  private_key = [d, n]

  return public_key, private_key
end

def encrypt(message, public_key)
  e, n = public_key
  message.bytes.map { |byte| (byte ** e) % n }
end

def decrypt(encrypted_message, private_key)
  d, n = private_key
  encrypted_message.map { |byte| (byte ** d) % n }.pack('C*').force_encoding('utf-8')
end
