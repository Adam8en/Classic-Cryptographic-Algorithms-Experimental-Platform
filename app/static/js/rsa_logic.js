// app/static/js/rsa_logic.js

layui.use(['form', 'layer', 'jquery'], function () {
    var form = layui.form;
    var layer = layui.layer;
    var $ = layui.jquery; // 获取jQuery对象

    // API 端点基础URL (你需要根据你的Flask蓝图配置来修改)
    var API_BASE_URL = '/api/rsa';

    // --- 1. 密钥生成 ---
    form.on('submit(generateKeysAction)', function (formData) {
        // ... (密钥生成的AJAX逻辑，确保ID选择器正确) ...
        var bitsValue = $('#key-bits-input').val();
        var eValue = $('#key-exp-input').val();

        if (!bitsValue || !eValue) {
            layer.alert('密钥位数和公钥指数 e 不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }
        if (parseInt(bitsValue) < 256) {
            layer.alert('密钥位数过小，可能不安全或无法生成。建议至少256位。', { icon: 7, title: '输入警告' });
        }

        layer.load(1);
        var payload = {
            bits: parseInt(bitsValue),
            e_value: parseInt(eValue)
        };
        console.log("发送密钥生成请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/generate_keys',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                $("#generateKeysResultArea").empty();

                if (response.success && response.keys) {
                    var keys = response.keys;
                    var resultHtml = "<fieldset class='layui-elem-field' style='margin-top: 15px;'><legend>生成的密钥</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>公钥 N:</strong>\n" + $('<div/>').text(keys.public_key_n).html() + "</pre>";
                    resultHtml += "<pre><strong>公钥 E:</strong>\n" + $('<div/>').text(keys.public_key_e).html() + "</pre>";
                    resultHtml += "<pre><strong>私钥 D (注意保密):</strong>\n" + $('<div/>').text(keys.private_key_d).html() + "</pre>";
                    if (keys.private_key_n_for_consistency) {
                        resultHtml += "<pre><strong>私钥 N (与公钥N相同):</strong>\n" + $('<div/>').text(keys.private_key_n_for_consistency).html() + "</pre>";
                    }
                    resultHtml += "</div></fieldset>";

                    $("#generateKeysResultArea").html(resultHtml);

                    // 自动填充到加密和解密表单
                    $('#publicKeyNEncryptInput').val(keys.public_key_n);
                    $('#publicKeyEEncryptInput').val(keys.public_key_e);
                    $('#privateKeyNDecryptInput').val(keys.public_key_n);
                    $('#privateKeyDDecryptInput').val(keys.private_key_d);

                    layer.msg(response.message || '密钥生成成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '密钥生成失败。';
                    $("#generateKeysResultArea").html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                $("#generateKeysResultArea").empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $("#generateKeysResultArea").html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });

    // --- 2. 明文加密 ---
    form.on('submit(encryptAction)', function (formData) {
        var plaintext = $('#plaintextEncryptInput').val();
        var publicKeyN = $('#publicKeyNEncryptInput').val();
        var publicKeyE = $('#publicKeyEEncryptInput').val();

        if (!plaintext || !publicKeyN || !publicKeyE) {
            layer.alert('进行加密操作，明文和公钥N、E均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }

        layer.load(1);
        var payload = {
            plaintext: plaintext,
            public_key_n: publicKeyN,
            public_key_e: publicKeyE
        };
        console.log("发送加密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/encrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                $("#encryptResultArea").empty();

                if (response.success && response.ciphertext_hex) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>加密结果</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>密文 (Hex):</strong>\n" + $('<div/>').text(response.ciphertext_hex).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $("#encryptResultArea").html(resultHtml);

                    $('#ciphertextDecryptInput').val(response.ciphertext_hex);

                    layer.msg(response.message || '加密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '加密失败。';
                    $("#encryptResultArea").html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                $("#encryptResultArea").empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $("#encryptResultArea").html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });

    // --- 3. 密文解密 ---
    form.on('submit(decryptAction)', function (formData) {
        var ciphertextHex = $('#ciphertextDecryptInput').val();
        var privateKeyN = $('#privateKeyNDecryptInput').val();
        var privateKeyD = $('#privateKeyDDecryptInput').val();

        if (!ciphertextHex || !privateKeyN || !privateKeyD) {
            layer.alert('进行解密操作，密文和私钥N、D均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }

        layer.load(1);
        var payload = {
            ciphertext_hex: ciphertextHex,
            private_key_n: privateKeyN,
            private_key_d: privateKeyD
        };
        console.log("发送解密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/decrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                $("#decryptResultArea").empty();

                if (response.success && response.decrypted_text !== undefined) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>解密结果</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>解密后明文:</strong>\n" + $('<div/>').text(response.decrypted_text).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $("#decryptResultArea").html(resultHtml);
                    layer.msg(response.message || '解密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '解密失败。';
                    $("#decryptResultArea").html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                $("#decryptResultArea").empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $("#decryptResultArea").html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });
});