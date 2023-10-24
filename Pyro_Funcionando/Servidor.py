import Pyro5.api
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import threading
from time import sleep

class Product:


    def __init__(self, codigo, nome, descricao, quantidade, preco, estoqueminimo):
        self.code = codigo
        self.name = nome
        self.description = descricao
        self.quantity = quantidade
        self.price = preco
        self.min_stock = estoqueminimo
        self.movements = []

    def add_entry(self, quantidade):
        self.quantity += quantidade
        self.movements.append((datetime.datetime.now(), "entrada", quantidade))

    def add_exit(self, quantidade):
        if self.quantity >= quantidade:
            self.quantity -= quantidade
            self.movements.append((datetime.datetime.now(), "saída", quantidade))

    def get_stock_status(self):
        return {
            "code": self.code,
            "name": self.name,
            "description": self.description,
            "quantity": self.quantity,
            "price": self.price,
            "min_stock": self.min_stock,
        }


class User:
    def __init__(self, nome, public_key, objetocliente):
        self.name = nome
        self.public_key = public_key
        self.client_object = objetocliente

class Estoque:
    def __init__(self):
        self.users = {} 
        self.products = {}  
        self.clients = {} 
        
    @Pyro5.api.expose
    def register_user(self, nome, public_key, client_object):
        print(public_key)
        print("Usuarios cadastrados: ", self.users)
        print("Name:", nome)
        if nome not in self.users:
            user = User(nome, public_key, client_object)
            self.users[nome] = user
            print(self.users[nome], self.users[nome].nome, self.users, self.users[nome].public_key)
            return f"Usuário {nome} registrado com sucesso."
        else:
            print("else")
            return f"Usuário {nome} já está registrado."


    @Pyro5.api.expose
    def record_entry(self, user_name, codigo, nome, description, quantity, price, min_stock, signature):
        if user_name in self.users:
            user = self.users[user_name]
            if codigo in self.products:
                print("Produto adicionado")
                product = self.products[codigo]
                # Verificar a assinatura digital com a chave pública do usuário
                if self.verify_signature(signature, user.public_key, user_name):
                    print("Assinatura digital válida.")
                    product.add_entry(quantity)
                    # Verificar se a quantidade após a entrada atingiu o estoque mínimo
                    if product.quantity <= product.min_stock:
                        self.notify_replenishment(product)
                    return f"Entrada de {quantity} unidades de {product.name} registrada."
                else:
                    print("Assinatura digital inválida.")
                    return "Assinatura digital inválida."
            else:
                print(nome, codigo)
                product = Product(codigo, nome, description, quantity, price, min_stock)
                self.products[codigo] = product
                self.products[codigo].add_entry(quantity)
                return f"Produto {nome} ({codigo}) adicionado ao estoque."

        else:
            return "Usuário não encontrado."

    @Pyro5.api.expose
    def record_exit(self, code, user_name, quantity, signature):
        if user_name in self.users:
            user = self.users[user_name]
            if code in self.products:
                product = self.products[code]
                # Verificar a assinatura digital com a chave pública do usuário
                if self.verify_signature(signature, user.public_key, user_name):
                    product.add_exit(quantity)
                    return f"Saída de {quantity} unidades de {product.name} registrada."
                else:
                    return "Assinatura digital inválida."
            else:
                return "Produto não encontrado."
        else:
            return "Usuário não encontrado."

    def verify_signature(self, signature, public_key, message):
        # Implemente a verificação da assinatura digital aqui
        # Use a chave pública para verificar a assinatura
        # Retorne True se a assinatura for válida, caso contrário, retorne False
        return True
        # Decodifique a base64
        public_key_bytes = base64.b64decode(public_key)

        # Carregue a chave pública PEM
        #public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

        print('tenta verificar assinatura:', message)
        print(public_key)
        try:
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True  # Assinatura válida
        except Exception as error:
            print(error)
            return False  # Assinatura inválida



        return True
    @Pyro5.api.expose
    def generate_stock_report(self, report_type):
        if report_type == 'PRODUTOS EM ESTOQUE':
            emEstoque = []
            for product in self.products.values():
                if product.quantity > product.min_stock:
                    product_info = {
                        "code": product.code,
                        "name": product.name,
                        "quantity": product.quantity
                    }
                    emEstoque.append(product_info)
            return emEstoque
                


    def check_low_stock(self):

        for product in self.products.values():
            if product.quantity <= product.min_stock:
                self.notify_replenishment(product)


    def check_unsold_products(self):

        recent_product_movements = self.generate_stock_report("Fluxo de movimentação")
        print(recent_product_movements)


        for product in self.products.values():
            counter = 0
            for info in product.movements:
                print(info[1])
                if info[1] == "saída":
                    counter += 1
        
            if counter == 0:
                self.notify_unsold_products(product)


    @Pyro5.api.expose 
    def notify_replenishment(self, product):#def notify_replenishment(self, user_name, product):
        # Método para notificar o gestor quando um produto atinge o estoque mínimo

        print(self.users)

        for user_name, user_object in self.users.items():
            print(f"Atenção Gestor {user_name} de objeto {user_object} e URI {user_object.client_object}, o produto {product.name} está fora de estoque")
            aux_object = Pyro5.api.Proxy(user_object.client_object)
            aux_object.notify_replenishment(product.code)
       
    @Pyro5.api.expose
    def notify_unsold_products(self, product):
        # Método para enviar relatórios periódicos sobre produtos não vendidos
        print("unsold products")
        for user_name, user_object in self.users.items():
            print(f"Atenção Gestor {user_name} de objeto {user_object} e URI {user_object.client_object}, o produto {product.name} não está sendo vendido")
            aux_object = Pyro5.api.Proxy(user_object.client_object)
            aux_object.notify_unsold_products(product.code)


    def __reduce__(self):
        return (self.__class__, (self.name, self.public_key))
    


# Configurar o servidor PyRO
if __name__ == "__main__":
    daemon = Pyro5.api.Daemon()
    ns = Pyro5.api.locate_ns()

    stock_system = Estoque()
    uri = daemon.register(stock_system)
    ns.register("estoque", uri)
    print("Servidor PyRO pronto.")

    check_stock_thread = threading.Thread(args=(stock_system, )).start()

    daemon.requestLoop()
