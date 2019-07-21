from bitcoinrpc.authproxy import AuthServiceProxy


class RPC:

    def __init__(self, uri):
        self.uri = uri

    def __getattr__(self, name):
        """Hack to establish a new AuthServiceProxy every time this is called"""
        rpc = AuthServiceProxy(self.uri)
        return getattr(rpc, name)


rpc_template = "http://%s:%s@%s:%s"

# TODO: move passwords to config
mainnet = RPC(rpc_template % ('bitcoin', 'python', 'localhost', 8332))
testnet = RPC(rpc_template % ('bitcoin', 'python', 'localhost', 18332))
