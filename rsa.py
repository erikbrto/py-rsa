import json
import re
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from datetime import datetime
from functools import partial
from hashlib import sha3_256, sha1
from os.path import abspath, isfile
from random import getrandbits

import gmpy2

from aes import AES, converter_str_hex

EXPOENTE_PADRAO = 65537

class ChaveRSA(object):

    def __getitem__(self, item):
        return getattr(self, item)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, ", ".join(["%s=%s" % (k, self.__dict__[k]) for k in self.__dict__]))


class ChavePublica(ChaveRSA):

    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e


class ChavePrivada(ChaveRSA):

    def __init__(self, p: int, q: int, n: int, d: int, e: int):
        self.p = p
        self.q = q
        self.n = n
        self.d = d
        self.e = e

    
class OAEP(object):

    @staticmethod
    def adicionar_padding(mensagem: str, qtd_bits_modulus: int) -> str:
        mensagem = converter_str_hex(mensagem)
        n  = qtd_bits_modulus - (8 * 11)
        k0 = 128
        k1 = n - k0 - (len(mensagem) * 8)
        r  = getrandbits(k0).to_bytes(16, "big")

        for _ in range(int(k1 / 8)):
            mensagem += b'\x00'

        g = partial(OAEP.gerar_mascara, len(mensagem))
        h = partial(OAEP.gerar_mascara, int(k0 / 8))
        x = OAEP.xor(mensagem, g(r))
        y = OAEP.xor(r, h(x))

        return (x + y).hex()

    
    @staticmethod
    def remover_padding(mensagem: str):
        mensagem = converter_str_hex(mensagem)
        k0 = 128
        x = bytes(mensagem)[:int(k0 / 8)]
        y = bytes(mensagem)[int(k0 / 8):]

        g = partial(OAEP.gerar_mascara, len(mensagem))
        h = partial(OAEP.gerar_mascara, int(k0 / 8))

        r = OAEP.xor(y, h(x))
        m = OAEP.xor(x, g(r))

        return m.hex()


    @staticmethod
    def i2osp(integer: int, size: int = 4) -> str:
        return "".join([chr((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])


    @staticmethod
    def gerar_mascara(qtd_bytes: int, dados: bytes):
        i = 0
        resultado = bytes()

        while len(resultado) < qtd_bytes:
            c = bytes(OAEP.i2osp(i), "utf-8")
            resultado += sha1(dados + c).digest()
            i += 1

        return resultado[:qtd_bytes]


    @staticmethod
    def xor(dados_a: bytes, dados_b: bytes):
        resultado = bytes()
        len_a = len(dados_a)
        len_b = len(dados_b)
        
        for i in range(min(len_a, len_b)):
            resultado += (dados_a[i] ^ dados_b[i]).to_bytes(1, "big")
        
        return resultado


class RSA(object):

    @staticmethod
    def gerar_chaves() -> tuple[ChavePublica, ChavePrivada]:
        p, q = RSA.gerar_numeros_primos()
        n    = p * q
        phi  = (p - 1) * (q - 1)
        e    = EXPOENTE_PADRAO
        d    = int(gmpy2.invert(e, phi))

        return (ChavePublica(n, e), ChavePrivada(p, q, n, d, e))


    @staticmethod
    def gerar_numeros_primos() -> tuple:
        numeros = []

        while len(numeros) < 2:
            n_aleatorio = getrandbits(512)

            if not gmpy2.is_prime(n_aleatorio):
                continue

            if (not numeros) or (numeros[0] != n_aleatorio):
                numeros.append(n_aleatorio)
        
        return tuple(numeros)


    @staticmethod
    def gerar_chave_sessao() -> str:
        return hex(getrandbits(128))[2:]


    @staticmethod
    def cifrar(mensagem: str, chave: ChavePrivada) -> bytes:
        mensagem    = int.from_bytes(bytes(mensagem, "utf-8"), "big")
        msg_cifrada = int(gmpy2.powmod(mensagem, chave.d, chave.n))

        return msg_cifrada.to_bytes(128, "big")


    @staticmethod
    def decifrar(mensagem: bytes, chave: ChavePublica) -> str:
        mensagem      = int.from_bytes(mensagem, "big")
        msg_decifrada = int(gmpy2.powmod(mensagem, chave.e, chave.n))

        return msg_decifrada.to_bytes(128, "big").strip(b"\x00").decode("utf-8")
    

    @staticmethod
    def salvar_chaves_arquivo(chave_publica: ChavePublica, chave_privada: ChavePrivada) -> tuple:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        arq_chave_publica = "chave_%s.pubkey" % timestamp
        arq_chave_privada = "chave_%s.prvkey" % timestamp
       
        with open(arq_chave_publica, "wt") as arq:
            json.dump(chave_publica.__dict__, arq)

        with open(arq_chave_privada, "wt") as arq:
            json.dump(chave_privada.__dict__, arq)

        return (abspath(arq_chave_publica), abspath(arq_chave_privada))


    @staticmethod
    def carregar_chaves_arquivo(arq_chave: str) -> ChavePublica | ChavePrivada:
        with open(arq_chave, "rt") as arq:
            chave_publica = json.load(arq)

        if arq_chave.endswith(".pubkey"):
            chave = ChavePublica(chave_publica["n"], chave_publica["e"])
        elif arq_chave.endsith(".prvkey"):
            chave = ChavePrivada(chave_publica["p"], chave_publica["q"], chave_publica["n"], 
                                 chave_publica["d"], chave_publica["e"])

        return chave


def criar_arquivo_assinado(arq_entrada: str, arq_saida: str, arq_chave_publica: str, arq_chave_privada: str) -> tuple:
    # Definicação do nome padrão do arquivo de saída, caso não especificado
    if not arq_saida:
        extensao = re.search(r"\.\w+$", arq_entrada)

        if extensao:
            arq_saida = re.sub(r"\.\w+$", "_cifrado%s" % extensao.group(0), arq_entrada)
        else:
            arq_saida = re.sub(r"\.\w+$", "_cifrado", arq_entrada)
    
    # Definição das chaves RSA, criando um novo par caso não especificado à partir de um arquivo
    if not arq_chave_publica or not arq_chave_privada:
        chave_publica, chave_privada = RSA.gerar_chaves()

        print("Arquivos de chaves criados\nChave Pública: [%s]\nChave Privada: [%s]" 
              % RSA.salvar_chaves_arquivo(chave_publica, chave_privada))
    else:
        chave_publica = RSA.carregar_chaves_arquivo(arq_chave_publica)
        chave_privada = RSA.carregar_chaves_arquivo(arq_chave_privada)

        print("Arquivos de chaves carregados\nChave Pública: [%s]\nChave Privada: [%s]" 
              % (abspath(arq_chave_publica), abspath(arq_chave_privada)))

    arq_chave_aes  = re.sub(r"\.\w+$", "_chave", arq_entrada)
    arq_assinatura = re.sub(r"\.\w+$", "_assinatura", arq_entrada)
    chave_sessao   = RSA.gerar_chave_sessao()
    aes            = AES(chave_sessao, 9)

    print("Chave de sessão para cifração AES criada: [%s]" % chave_sessao)

    # Leitura dos dados do arquivo de entrada
    with open(arq_entrada, "rb") as arq:
        dados_entrada = arq.read()

    # Escrita dos dados no arquivo de saída após cifração AES e formatação em Base64
    # e cálculo do hash SHA-3 do arquivo cifrado
    print("Iniciando cifração AES do arquivo: [%s]" % abspath(arq_entrada))

    with open(arq_saida, "wt") as arq:
        dados_saida    = b64encode(aes.cifrar(dados_entrada, "ECB"))
        hash_arq_saida = sha3_256(dados_saida).hexdigest()

        arq.write(dados_saida.decode("ascii"))
        print("Arquivo cifrado salvo: [%s]" % abspath(arq_saida))
        print("Hash SHA-3 do arquivo cifrado: [%s]" % hash_arq_saida)

    # Cifração RSA da chave de sessão AES e escrita em arquivo
    with open(arq_chave_aes, "wb") as arq:
        arq.write(RSA.cifrar(chave_sessao, chave_privada))
    print("Chave de sessão salva: [%s]" % abspath(arq_chave_aes))
    

    # Cifração RSA do hash SHA-3 do arquivo cifrado e escrita em arquivo
    with open(arq_assinatura, "wb") as arq:
        arq.write(RSA.cifrar(hash_arq_saida, chave_privada))
    print("Hash SHA-3 do arquivo cifrado salvo: [%s]" % abspath(arq_assinatura))

    return (arq_saida, arq_chave_aes, arq_assinatura)


def checar_arquivo_assinado(arq_entrada: str, arq_saida: str, arq_chave_publica: str, arq_chave_aes: str, arq_hash_assinatura: str) -> bool:
    # Verificações do arquivo de chave RSA pública
    if not isfile(arq_chave_publica):
        print("[%s] arquivo de chave pública não encontrado!" % arq_chave_publica)
        return
    elif not arq_chave_publica.endswith(".pubkey"):
        print("[%s] arquivo de chave pública inválido!" % arq_chave_publica)
        return

    # Definicação do nome padrão do arquivo de saída, caso não especificado
    if not arq_saida:
        extensao = re.search(r"\.\w+$", arq_entrada)

        if extensao:
            arq_saida = re.sub(r"\.\w+$", "_decifrado%s" % extensao.group(0), arq_entrada)
        else:
            arq_saida = re.sub(r"\.\w+$", "_decifrado", arq_entrada)

    chave_publica = RSA.carregar_chaves_arquivo(arq_chave_publica)

    print("Arquivo de chave pública RSA carregado: [%s]" % abspath(arq_chave_publica))

    # Decifração RSA do hash SHA-3 do arquivo de assinatura
    with open(arq_hash_assinatura, "rb") as arq:
        hash_assinatura = RSA.decifrar(arq.read(), chave_publica)
    
    # Leitura dos dados cifrados e cálculo do hash SHA-3 do arquivo de entrada
    with open(arq_entrada, "rt") as arq:
        dados_entrada = arq.read()
        hash_arq_entrada = sha3_256(dados_entrada.encode("ascii")).hexdigest()

    print("Hash SHA-3 arquivo de entrada: %s" % hash_arq_entrada)
    print("Hash SHA-3 assinatura: %s" % hash_assinatura)
    
    # Validação final da assinatura do arquivo e criação do arquivo de saída após
    # decifração AES recriando o arquivo original
    if hash_assinatura == hash_arq_entrada: 
        print("O Hash SHA-3 da assinatura e do arquivo são iguais.")

        # Leitura e decifração RSA do arquivo de chave de sessão AES
        with open(arq_chave_aes, "rb") as arq:
            chave_aes = RSA.decifrar(arq.read(), chave_publica)
            aes = AES(chave_aes, 9)

        print("Chave de sessão para cifração AES: [%s]" % chave_aes)
        print("Iniciando decifração AES do arquivo: [%s]" % abspath(arq_entrada))

        # Escrita dos dados no arquivo de saída após decodificação em Base64 e 
        # decifração AES recriando o arquivo original
        with open(arq_saida, "wb") as arq:
            dados_saida = aes.decifrar(b64decode(dados_entrada), "ECB")
            arq.write(dados_saida)

        print("Arquivo decifrado salvo: [%s]" % abspath(arq_saida))

        return True
    else:
        print("O Hash SHA-3 da assinatura e do arquivo NÃO são iguais.")
        return False


def main(args):
    if not isfile(args.arquivo_entrada):
        print("Não foi possível abrir o arquivo em [%s]." % args.arquivo_entrada)
        return

    if args.assinar:
        criar_arquivo_assinado(args.arquivo_entrada, args.arquivo_saida, args.pub_key, args.priv_key)
    elif args.verificar:
        if not args.pub_key or not args.aes or not args.hash:
            print("""Para verificação de assinatura devem ser especificados os argumentos: \
                   \n-- Chave Pública \t(--pub-key)\n-- Chave de Sessão AES \t(--aes)\n-- Hash de Assinatura \t(--hash)""")
            return

        checar_arquivo_assinado(args.arquivo_entrada, args.arquivo_saida, args.pub_key, args.aes, args.hash)


if __name__ == "__main__":
    parser   = ArgumentParser(description="Aplicação de geração e verificação assinaturas RSA em arquivos.")
    operacao = parser.add_mutually_exclusive_group(required=True)
    arquivos = parser.add_argument_group("arquivos")
    chaves = parser.add_argument_group("chaves")

    operacao.add_argument("-a", "--assinar", action="store_true", help="executar criação de assinatura de arquivo")
    operacao.add_argument("-v", "--verificar", action="store_true", help="executar verificação de assinatura de arquivo")
    arquivos.add_argument("arquivo_entrada", type=str, help="arquivo a assinar ou verificar")
    arquivos.add_argument("arquivo_saida", type=str, nargs="?", help="(opcional) arquivo gerado após assinatura ou verificação")
    arquivos.add_argument("--aes", type=str, help="arquivo contendo chave de sessão AES")
    arquivos.add_argument("--hash", type=str, help="arquivo contendo hash de assinatura")
    chaves.add_argument("--pub-key", type=str, help="arquivo contendo informações de chave pública")
    chaves.add_argument("--priv-key", type=str, help="arquivo contendo informações de chave privada")
    
    main(parser.parse_args())
