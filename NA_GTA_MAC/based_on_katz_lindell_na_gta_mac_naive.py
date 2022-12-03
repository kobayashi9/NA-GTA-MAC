import binascii
import os
import math
import hmac
import hashlib
import numpy as np
import sys

p  = 32 #セキュリティパラメータ
d = 1 #検知できる陽性の数

path1 = "./test/100_1.txt" #改ざん前のメッセージファイル
path2 = "./test/100_2.txt" #改ざん後のメッセージファイル

#ファイル読み込み
with open(path1, "r") as f:
	msg_list = f.readlines()
	for i in range(len(msg_list)):
		msg_list[i] = msg_list[i].replace("\n","")

with open(path2, "r") as f:
	vfy_msg_list = f.readlines()
	for i in range(len(vfy_msg_list)):
		vfy_msg_list[i] = vfy_msg_list[i].replace("\n","") 
"""
id,メッセージのリスト作成
==========================
	id_num : idの総数(int型)
	msg_list : メッセージのリスト(bytes型)
==========================
"""
def make_im_tuples(id_num, msg_):
	msg_list = change_strtobytes(msg_)#メッセージの集合をstr型→bytes型にキャスト
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
def make_imt_tuples(im_tuples_list,tags_list):
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
u × nの行列生成
==========================
	id_num : メッセージの総数
	matrix : u × nの行列
==========================
"""
def make_gtmatrix(id_num):
	count = 0
	gx = make_primelist(id_num)
	matrix = np.zeros((sum(gx), id_num))
	for l in range(len(gx)):
		for j in range(id_num):
			for i in range(gx[l]):
				if i == j%gx[l]:
					matrix[count+i][j] = 1
		count += gx[l]
	return matrix
"""
メッセージの総数に対してのNon-adaptive group-testingをするためのもの
==========================
	id_num : メッセージの総数
	gx_list : リストでありリストの総和がu × nの行列のuになる。
	※一つの要素が√n以上であり、それがd+1個で全ての要素が互いに素である。
	なおかつ、そのリストの総和が生成することのできる総和で最小でなければならない。
==========================
"""
def make_primelist(id_num):
	gx_list = []
	base = math.ceil(np.sqrt(id_num))
	i = 0
	while i < d+1:
		if i == 0:
			gx_list.append(base)
			i += 1
		else:
			base += 1
			for j in range(len(gx_list)):
				if math.gcd(base, gx_list[j]) != 1:
					break
				elif j == len(gx_list)-1: #リストの最後の要素までたどり着いたら(すべての要素において互いに素のとき)
					gx_list.append(base)
					i += 1	
				else:
					continue
	return gx_list
"""
Group-Testing tagの作成
==========================
	imt_tuples_list : id,メッセージ,tagのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
	matrix : グループテストを実行するための行列(テスト × サンプル)
==========================
"""
def make_gtatag(imt_tuples_list):
	n = len(imt_tuples_list)
	matrix = make_gtmatrix(n)
	len_matrix = len(matrix)
	Tu_list = [0 for _ in range(len_matrix)]
	for i in range(len_matrix):
		for j in range(n):
			if (Tu_list[i] == 0 and matrix[i][j] == 1):
				Tu_list[i] = int(imt_tuples_list[j][2], 16)
			elif(matrix[i][j] == 1):
				Tu_list[i] ^= int(imt_tuples_list[j][2],16)
			else :
				continue
	return Tu_list
"""
グループテストタグ検証(検証部分)
==========================
	vfy_im_tuples_list : id,メッセージのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
	vfy_Tu_list : 検証者が作成するグループテストタグのリスト(bytes型)
	gt_matrix : u × nの行列
	Js_list : 最終的に改ざんされたid,メッセージが格納されるリスト
==========================
"""
def remove_id(vfy_im_tuples_list, Tu_list, vfy_Tu_list, gt_matrix):
	Js_list = dict(vfy_im_tuples_list)
	gtt_num = len(Tu_list)
	sample_num = len(vfy_im_tuples_list)
	for i in range(gtt_num):
		if(Tu_list[i] == vfy_Tu_list[i]): #タグが一致しているとき
			for j in range(sample_num):
				if(gt_matrix[i][j] == 1 and (j in Js_list)):
					Js_list.pop(j)
		else:
			continue
	return  Js_list
"""
グループテストタグ検証(検証全体)
==========================
	sc_keys_list : 秘密鍵のリスト(中身bytes型)
	im_tuples_list : id,メッセージのリスト
	Tu_list : グループテストタグのリスト(bytes型?)
	vfy_tags_list : 検証用のタグのリスト(中身byte型)
	vfy_imt_tuples_list : 検証用のid,メッセージ,tagのリスト
	vfy_Tu_list : 検証者が作成するグループテストタグのリスト(bytes型?)
	matrix : グループテストを実行するための行列(テスト × サンプル)
	Js_list : 最終的に改ざんされたid,メッセージが格納されるリスト
==========================
"""
def verify_gtatag(sc_keys_list, vfy_im_tuples_list, Tu_list):
	vfy_tags_list = make_tags(sc_keys_list, vfy_im_tuples_list)
	vfy_imt_tuples_list = make_imt_tuples(vfy_im_tuples_list, vfy_tags_list)
	matrix = make_gtmatrix(len(vfy_imt_tuples_list))
	vfy_Tu_list = make_gtatag(vfy_imt_tuples_list)
	Js_ = remove_id(vfy_im_tuples_list, Tu_list, vfy_Tu_list, matrix) #グループテストの検証をしている部分(Jsの中身が改ざんされたメッセージ)
	return Js_

def main():
	id_num =  len(msg_list) #idの総数
	im_tuples_list = make_im_tuples(id_num, msg_list) #id,msgの組のリスト生成
	sc_keys_list = make_sckeys(p, id_num) #秘密鍵のリスト生成
	tags_list = make_tags(sc_keys_list, im_tuples_list) #タグのリスト生成
	imt_tuples_list = make_imt_tuples(im_tuples_list, tags_list) #id,メッセージ,tagのリスト生成
	Tu_list = make_gtatag(imt_tuples_list) # グループテスト用タグ生成

	#検証
	vfy_im_tuples_list = make_im_tuples(id_num, vfy_msg_list) #id,msgの組のリスト生成
	Js_list = verify_gtatag(sc_keys_list, vfy_im_tuples_list, Tu_list)
	print(Js_list)
if __name__ == '__main__':
	main()