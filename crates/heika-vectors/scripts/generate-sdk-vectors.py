# SPDX-License-Identifier: MIT
# /// script
# requires-python = ">=3.10"
# dependencies = ["symbol-sdk-python==3.3.3"]
# ///
"""公式の Python SDK で署名したトランザクションを、決定的に作って JSON に書き出す。

`uv run crates/heika-vectors/scripts/generate-sdk-vectors.py > crates/heika-vectors/testdata/sdk-transactions.json`

鍵は、誰でも知っているテスト用のニーモニック（test を11個並べて最後が junk）から、
SDK の bip32_path で導出する。このアカウントには何も送らない。
鍵以外の値は、SHA-256("<ラベル>/<番号>") から切り出すので、何度動かしても同じものが出る。
"""

import hashlib
import json
import sys

from symbolchain.Bip32 import Bip32
from symbolchain.facade.SymbolFacade import SymbolFacade

MNEMONIC = ' '.join(['test'] * 11 + ['junk'])
SDK = 'symbol-sdk-python 3.3.3'
COUNT = 16
TYPES = [
	'account_key_link_transaction_v1',
	'node_key_link_transaction_v1',
	'vrf_key_link_transaction_v1',
	'transfer_transaction_v1',
]

ROOT = Bip32().from_mnemonic(MNEMONIC, '')
FACADES = {name: SymbolFacade(name) for name in ['mainnet', 'testnet']}


def draw(label, index):
	"""label と番号から決まる32バイト。"""
	return hashlib.sha256(f'{label}/{index}'.encode()).digest()


def u64(label, index):
	return int.from_bytes(draw(label, index)[:8], 'little')


def key_pair(facade, account):
	return facade.bip32_node_to_key_pair(ROOT.derive_path(facade.bip32_path(account)))


def recipient_address(facade, name, index):
	"""同じニーモニックの別のアカウントのアドレスか、ネームスペースを指すアドレス。"""
	if draw(f'{name}/recipient-kind', index)[0] % 2:
		# ネットワークの1バイトの最下位ビットを立て、ネームスペースの ID を続けて、残りを0で埋める
		namespace_id = u64(f'{name}/namespace-id', index) | (1 << 63)
		return bytes([facade.network.identifier | 1]) + namespace_id.to_bytes(8, 'little') + bytes(15)
	account = 1000 + draw(f'{name}/recipient-account', index)[0]
	return facade.network.public_key_to_address(key_pair(facade, account).public_key).bytes


def mosaics(name, index):
	"""0から4種類。ID の最上位ビットが立っているものはネームスペースを指す。"""
	count = draw(f'{name}/mosaic-count', index)[0] % 5
	return [
		{'mosaic_id': u64(f'{name}/mosaic-id/{slot}', index), 'amount': u64(f'{name}/mosaic-amount/{slot}', index)}
		for slot in range(count)
	]


def message(name, index):
	"""空、UTF-8 の文、バイト列のどれか。"""
	kind = draw(f'{name}/message-kind', index)[0] % 3
	if 0 == kind:
		return b''
	if 1 == kind:
		return f'heika のテスト {index} 番 ✓'.encode()
	return draw(f'{name}/message-bytes', index)[:draw(f'{name}/message-length', index)[0] % 33]


def body(facade, name, index):
	if 'transfer_transaction_v1' == name:
		return {
			'recipient_address': recipient_address(facade, name, index),
			'mosaics': mosaics(name, index),
			'message': message(name, index),
		}
	return {
		'linked_public_key': draw(f'{name}/linked-public-key', index),
		'link_action': 'link' if draw(f'{name}/link-action', index)[0] % 2 else 'unlink',
	}


def vector(name, index):
	network = 'mainnet' if draw(f'{name}/network', index)[0] % 2 else 'testnet'
	facade = FACADES[network]
	account = index
	signer = key_pair(facade, account)
	transaction = facade.transaction_factory.create({
		'type': name,
		'signer_public_key': signer.public_key,
		'fee': u64(f'{name}/fee', index),
		'deadline': u64(f'{name}/deadline', index),
		**body(facade, name, index),
	})
	signature = facade.sign_transaction(signer, transaction)
	facade.transaction_factory.attach_signature(transaction, signature)

	fields = {
		'type': name,
		'network': network,
		'account': account,
		'signer_public_key': str(signer.public_key),
		'fee': transaction.fee.value,
		'deadline': transaction.deadline.value,
	}
	if 'transfer_transaction_v1' == name:
		fields['recipient_address'] = transaction.recipient_address.bytes.hex().upper()
		# 書くときと同じく、SDK が並べ替える前の順のまま残す
		fields['mosaics'] = mosaics(name, index)
		fields['message'] = bytes(transaction.message).hex().upper()
	else:
		fields['linked_public_key'] = str(transaction.linked_public_key)
		fields['link_action'] = str(transaction.link_action).split('.')[-1].lower()
	return {
		**fields,
		'signature': str(signature),
		'hash': str(facade.hash_transaction(transaction)),
		'payload': transaction.serialize().hex().upper(),
	}


def main():
	document = {
		'sdk': SDK,
		'mnemonic': MNEMONIC,
		'networks': {
			name: {
				'identifier': facade.network.identifier,
				'generation_hash_seed': str(facade.network.generation_hash_seed),
			}
			for name, facade in FACADES.items()
		},
		'transactions': [vector(name, index) for name in TYPES for index in range(COUNT)],
	}
	json.dump(document, sys.stdout, ensure_ascii=False, indent='\t')
	sys.stdout.write('\n')


if '__main__' == __name__:
	main()
