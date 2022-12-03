import binascii
import os
import math
import hmac
import hashlib
import numpy as np
import sys

p  = 32 #セキュリティパラメータ

path1 = "./test/100_1.txt" #改ざん前のメッセージファイル
path2 = "./test/100_2.txt" #改ざん後のメッセージファイル

#ファイル読み込み
with open(path1, "r") as f:
	msg_list = f.readlines()
	for i in range(len(msg_list)):
		msg_list[i] = msg_list[i].replace("\n","")

with open(path2, "r") as f:
	vfy_msg_list = f.readlines()
	for i in range(len(msg_list)):
		vfy_msg_list[i] = vfy_msg_list[i].replace("\n","") 

"""
id,メッセージのリスト作成
==========================
	id_num : idの総数(int型)
	msg_list : メッセージのリスト(bytes型)
==========================
"""
def make_im_tuples(id_num, msg_list):
	msg_list = change_strtobytes(msg_list)#メッセージの集合をstr型→bytes型にキャスト
	im_tuples_list = []
	for i in range(id_num):
		im_tuples_list.append([i, msg_list[i]])
	return im_tuples_list
"""
id,メッセージ,tagのリスト作成
==========================
	im_tuples_list : id,メッセージのリスト
	msg_list : メッセージのリスト(中身bytes型)
	imt_tuples_list : id,メッセージ,tagのリスト
==========================
"""
def make_imt_tuples(im_tuples_list, tags_list):
	imt_tuples_list = []
	for i in range(len(im_tuples_list)):
		imt_tuples_list.append([im_tuples_list[i][0],im_tuples_list[i][1], tags_list[i]])
	return imt_tuples_list
"""
str型→byte型にキャスト
==========================
	msg_list : メッセージのリスト(str型)
	msg_byte_list : メッセージのリスト(bytes型)
==========================
"""
def change_strtobytes(msg_list):
	msg_byte_list = []
	for i in msg_list:
		msg_byte_list.append(i.encode('utf-8'))
	return msg_byte_list
"""
秘密鍵の作成
==========================
	p : セキュリティパラメータ(int型)
	id_num : idの総数(int型)
	sc_keys_list : 秘密鍵のリスト(bytes型)
==========================
"""
def make_sckeys(p, id_num):
	sc_keys_list = []
	for i in range(id_num):
		sc_keys_list.append(os.urandom(p))
	return sc_keys_list
"""
タグの作成
==========================
	sc_keys_list : 秘密鍵のリスト(bytes型)
	im_tuples_list : id, メッセージのリスト
	tags_list : タグのリスト(中身str型)
==========================
"""
def make_tags(sc_keys_list, im_tuples_list):
	tags_list = []
	for i in range(len(im_tuples_list)):
		tags_list.append(hmac.new(sc_keys_list[i], im_tuples_list[i][1], hashlib.sha256).hexdigest())
	return tags_list
"""
集約タグの作成
==========================
	tags_list : タグのリスト(中身str型)
	aggregate_tag : 集約タグ(int型)
==========================
"""
def make_atag(tags_list):
	aggregate_tag = int(tags_list[0], 16)
	for i in range(1,len(tags_list)):
		aggregate_tag ^= int(tags_list[i], 16)
		return aggregate_tag
"""
集約タグの検証
==========================
	sc_keys_list : 秘密鍵のリスト(bytes型)
	vfy_im_tuples_list : id, メッセージのリスト
	aggregate_tag : 集約タグ(int型)
	vfy_aggregate_tag : 検証用集約タグ(int型)
==========================
"""
def verify_atag(sc_keys_list, vfy_im_tuples_list, aggregate_tag):
	vfy_tags_list = make_tags(sc_keys_list, vfy_im_tuples_list)
	vfy_aggregate_tag = make_atag(vfy_tags_list)
	if aggregate_tag != vfy_aggregate_tag:
		return True
	else:
		return False

def main():
	id_num =  len(msg_list) #idの総数
	im_tuples_list = make_im_tuples(id_num, msg_list) #id,msgの組のリスト生成
	sc_keys_list = make_sckeys(p, id_num) #秘密鍵のリスト生成
	tags_list = make_tags(sc_keys_list, im_tuples_list) #タグのリスト生成
	imt_tuples_list = make_imt_tuples(im_tuples_list, tags_list) #id,メッセージ,tagのリスト生成
	aggregate_tag = make_atag(tags_list) # グループテスト用タグ生成
	#検証
	vfy_im_tuples_list = make_im_tuples(id_num, vfy_msg_list) #id,msgの組のリスト生成
	if verify_atag(sc_keys_list, vfy_im_tuples_list, aggregate_tag):
		print("Tampering detection")
	else:
		print("No problem")

if __name__ == '__main__':
	main()