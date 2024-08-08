import const


def str_to_bin(user_input):
    res = ''
    
    for char in user_input:
        binary_char = format(ord(char), '08b')
        res += binary_char


    if len(res) > 64:
        res = res[:64]
    else:
        res = res.ljust(64, '0')

    return res


def binary_to_ascii(str):
    ascii_str = ''.join([chr(int(str[i:i+8], 2)) for i in range(0, len(str), 8)])
    return ascii_str


def ip_func(text):
    
    ip_result = [None] * 64
    c = 64
    for i in range(64):
        
        ip_result[i] = text[const.ip_table[i]-1]
        c -=1


    ip_res = ''.join(ip_result)
    
    return ip_res


def keygen():
    
    original_key = 'hereakey'
    key = ''
    
    for char in original_key:
        binary_key = format(ord(char), '08b') 
        key += binary_key

    return key


def subkeygen():
    
    key = keygen()
    pc1_key = ''.join(key[bit - 1] for bit in const.pc1_table)

    l = pc1_key[:28]
    r = pc1_key[28:]
    subkeys = []
    for num in range(16):
        l = l[const.shift_schedule[num]:] + l[:const.shift_schedule[num]]
        r = r[const.shift_schedule[num]:] + r[:const.shift_schedule[num]]
        lr_str = l + r
        sub_key = ''.join(lr_str[bit - 1] for bit in const.pc2_table)
        subkeys.append(sub_key)
    return subkeys


def encryption(user_input):
    bin_text = str_to_bin(user_input)
    subkeys = subkeygen()
    ip_res = ip_func(bin_text)
    lpt = ip_res[:32]
    rpt = ip_res[32:]
    for num in range(16):
        e_res = [rpt[i - 1] for i in const.e_box_table]
        e_res_str = ''.join(e_res)
        round_key_str = subkeys[num]
        xor_res = ''
        for i in range(48):
            xor_res += str(int(e_res_str[i]) ^ int(round_key_str[i]))

        grp = [xor_res[i:i+6] for i in range(0, 48, 6)]
        s_box_res = ''
        for i in range(8):
            row_bits = int(grp[i][0] + grp[i][-1], 2)
            col_bits = int(grp[i][1:-1], 2)
            s_box_val = const.s_boxes[i][row_bits][col_bits]
            s_box_res += format(s_box_val, '04b')

        p_box_res = [s_box_res[i - 1] for i in const.p_box_table]
        lpt_list = [i for i in lpt]
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_res[i])) for i in range(32)]
        lpt = rpt
        rpt = ''.join(new_rpt)
    
    tmp = rpt + lpt
    cipher = [tmp[const.ip_inverse_table[i] - 1] for i in range(64)]
    res = binary_to_ascii(''.join(cipher))
    
    return res

def decryption(final_cipher):
    bin_text = str_to_bin(final_cipher)
    subkeys = subkeygen()
    ip_res = ip_func(bin_text)
    
    lpt = ip_res[:32]
    rpt = ip_res[32:]

    for num in range(16):
        e_res = [rpt[i - 1] for i in const.e_box_table]
        e_res_str = ''.join(e_res)

        round_key_str = subkeys[15-num]

        xor_res = ''
        for i in range(48):
            xor_res += str(int(e_res_str[i]) ^ int(round_key_str[i]))
        grp = [xor_res[i:i+6] for i in range(0, 48, 6)]
        s_box_res = ''
        for i in range(8):
            row_bits = int(grp[i][0] + grp[i][-1], 2)
            col_bits = int(grp[i][1:-1], 2)
            s_box_value = const.s_boxes[i][row_bits][col_bits]
            s_box_res += format(s_box_value, '04b')

        p_box_res = [s_box_res[i - 1] for i in const.p_box_table]
        lpt_list = [i for i in lpt]
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_res[i])) for i in range(32)]
        lpt = rpt
        rpt = ''.join(new_rpt)
    
    tmp = rpt + lpt
    cipher = [tmp[const.ip_inverse_table[i] - 1] for i in range(64)]
    res = binary_to_ascii(''.join(cipher))

    return res