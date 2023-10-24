import Pyro5.api
import threading
import inquirer
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
Pyro5.api.config.SERIALIZER = 'marshal'
#Gera as chaves
def keysGenerator():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  
        key_size=2048,  
        backend=default_backend()
    )

    # Obter a chave pública correspondente
    public_key = private_key.public_key()

    # Serializar as chaves para armazenamento ou transmissão
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Salvar as chaves em arquivos
    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)

    print("CHAVES GERADAS AUTOMATICAMENTE! AS CHAVES FORAM GRAVADAS NA PASTA RAIZ")
    return [private_key_pem, public_key_pem, private_key]



# Classe de Gestão do Estoque
class Estoque:

    #Códigos de Notificações
    @Pyro5.api.expose 
    def reposicao(self, product_code):
        print("Necessário reposição do produto {product_code}")


# Função para assinar uma mensagem com a chave privada
def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# Configurar o cliente PyRO
if __name__ == "__main__":
    daemon = Pyro5.api.Daemon()
    uri = daemon.register(Estoque())
    keys = keysGenerator()
    private_key = keys[0]
    public_key = keys[1]
    pk = keys[2]
    servidor_nomes = Pyro5.api.locate_ns()
    server_uri = servidor_nomes.lookup("estoque")
    server = Pyro5.api.Proxy(server_uri) 
    print("SEJA BEM VINDO AO SISTEMA DE ESTOQUE! ")
    print("LOGIN DE USUÁRIO: ")
    name = input("NOME: ")
    response = server.register_user(name, public_key, uri)
    print(response)

    threading.Thread(target=daemon.requestLoop).start()

    message = name
    signature = sign_message(message, pk)
    
    while(True):
        questions = [
                inquirer.List('action', message="MENU", 
                            choices=['ENTRADA', 'SAÍDA', 'RELATÓRIO'],)

        ]
        answer = inquirer.prompt(questions)
        if(answer['action'] == 'ENTRADA'):
                produto = input("Produto que deseja adicionar: ")
                descricao = input("Descrição: ")
                quantidadestr = input("Quantidade: ")
                quantidade = int(quantidadestr)
                server.record_entry(name, 1, produto, descricao , quantidade, 5.5, 50, signature)
                print("PRODUTO REGISTRADO COM SUCESSO")
        elif(answer['action'] == 'SAÍDA'):
                print('Saida de produtos')
                server.record_exit(1, name, 10, signature)
        elif(answer['action'] == 'RELATÓRIO'):
                print('Relatorio')
                questions2 = [
                inquirer.List('action2', message="QUAL RELATÓRIO DESEJA EMITIR", 
                            choices=['PRODUTOS EM ESTOQUE'])

                ]
                answer = inquirer.prompt(questions2)
                if(answer['action2']== 'PRODUTOS EM ESTOQUE'):
                    print('PRODUTOS EM ESTOQUE')
                    produtosEmEstoque= server.generate_stock_report('PRODUTOS EM ESTOQUE')
                    for product in produtosEmEstoque:
                        print(f"Produto {product['name']} ({product['code']}) {product['quantity']} em estoque")