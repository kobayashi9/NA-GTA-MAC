import binascii
import os
import math
import hmac
import numpy as np
import hashlib
import sys

p  = 32 #セキュリティパラメータ
d = 1 #検知できる陽性の数

path1 = "./test/100_1.txt" #改ざん前のメッセージファイル
path2 = "./test/100_2.txt" #改ざん後のメッセージファイル

with open(path1, "r") as f:
	msg_list = f.readlines()
	for i in range(len(msg_list)):
		msg_list[i] = msg_list[i].replace("\n","")

with open(path2, "r") as f:
	vfy_msg_list = f.readlines()
	for i in range(len(vfy_msg_list)):
		vfy_msg_list[i] = vfy_msg_list[i].replace("\n","") 

def make_im_tuples(id_num, msg_list):
	msg_list = change_strtobytes(msg_list)#メッセージの集合をstr型→bytes型にキャスト
	im_tuples_list = []
	for i in range(id_num):
		im_tuples_list.append([i, msg_list[i]])
	return im_tuples_list

def make_imt_tuples(im_tuples_list, tags_list):
	imt_tuples_list = []
	for i in range(len(im_tuples_list)):
		imt_tuples_list.append([im_tuples_list[i][0],im_tuples_list[i][1], tags_list[i]])
	return imt_tuples_list

def change_strtobytes(msg_list):
	msg_byte_list = []
	for i in msg_list:
		msg_byte_list.append(i.encode('utf-8'))
	return msg_byte_list

def make_sckeys(p, id_num):
	sc_keys_list = []
	for i in range(id_num):
		sc_keys_list.append(os.urandom(p))
	return sc_keys_list

def make_tags(sc_keys_list, im_tuples_list):
	tags_list = []
	for i in range(len(im_tuples_list)):
		tags_list.append(hmac.new(sc_keys_list[i], im_tuples_list[i][1], hashlib.sha256).hexdigest())
	return tags_list

def make_gtmatrix(id_num):
	count = 0
	gx_list = make_primelist(id_num)
	matrix = np.zeros((sum(gx_list), id_num))
	for l in range(len(gx_list)):
		for j in range(id_num):
			for i in range(gx_list[l]):
				if i == j%gx_list[l]:
					matrix[count+i][j] = 1
		count += gx_list[l]
	return matrix

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

def make_gtatag(imt_tuples_list):
	n = len(imt_tuples_list)
	matrix = make_gtmatrix(n)
	len_matrix = len(matrix)
	Tu_list = [-1 for _ in range(len_matrix)]
	for i in range(len_matrix):
		temp = ""
		for j in range(n):
			if(temp is None):
				temp = imt_tuples_list[j][2]
			elif (matrix[i][j] == 1):
				temp += imt_tuples_list[j][2]
			else:
				continue
		temp = temp.encode('utf-8')
		Tu_list[i] = hashlib.sha256(temp).hexdigest()
	return Tu_list

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

def verify_gtatag(sc_keys_list, vfy_im_tuples_list, Tu_list):
	vfy_tags_list = make_tags(sc_keys_list, vfy_im_tuples_list)
	vfy_imt_tuples_list = make_imt_tuples(vfy_im_tuples_list, vfy_tags_list)
	matrix = make_gtmatrix(len(vfy_imt_tuples_list))
	vfy_Tu_list = make_gtatag(vfy_imt_tuples_list)
	Js_list = remove_id(vfy_im_tuples_list, Tu_list, vfy_Tu_list, matrix)
	return Js_list

def verify_tag(sc_keys_list, vfy_im_tuples_list, imt_tuples_list):
	Js_list = []
	vfy_tags_list = make_tags(sc_keys_list, vfy_im_tuples_list)
	for i in range(len(imt_tuples_list)):
		if(vfy_tags_list[i] != imt_tuples_list[i][2]):
			Js_list.append(i)
	return Js_list


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