// app/static/js/elgamal_logic.js

layui.use(['form', 'layer', 'jquery'], function () {
    var form = layui.form;
    var layer = layui.layer;
    var $ = layui.jquery;

    // API 端点基础URL (根据你的Flask蓝图配置来修改)
    var API_BASE_URL = '/api/elgamal'; // 确保与后端路由匹配

    // --- 1. ElGamal 密钥生成 ---
    form.on('submit(elgamalGenerateKeysFilter)', function (formData) {
        var bitsValue = $('#elgamal-key-bits-input').val();

        if (!bitsValue) {
            layer.alert('密钥位数不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }
        if (parseInt(bitsValue) < 256) { // ElGamal的p也需要足够大
            layer.alert('密钥位数过小，建议至少256位。', { icon: 7, title: '输入警告' });
        }

        layer.load(1);
        var payload = {
            bits: parseInt(bitsValue)
        };
        console.log("发送ElGamal密钥生成请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/generate_keys',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                // 假设你有一个总的密钥生成结果区，或者多个独立的显示区
                // 如果用总结果区:
                var resultContainerId = "#elgamalGenerateKeysResultArea"; // 假设的ID
                $(resultContainerId).empty(); 

                if (response.success && response.keys) {
                    var keys = response.keys;
                    var resultHtml = "<fieldset class='layui-elem-field' style='margin-top: 15px;'><legend>生成的ElGamal密钥</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>公钥 P:</strong>\n" + $('<div/>').text(keys.public_key_p).html() + "</pre>";
                    resultHtml += "<pre><strong>公钥 G:</strong>\n" + $('<div/>').text(keys.public_key_g).html() + "</pre>";
                    resultHtml += "<pre><strong>公钥 Y:</strong>\n" + $('<div/>').text(keys.public_key_y).html() + "</pre>";
                    resultHtml += "<pre><strong>私钥 X (注意保密):</strong>\n" + $('<div/>').text(keys.private_key_x).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);

                    // 自动填充到加密和解密表单
                    $('#elgamalPublicKeyPEncryptInput').val(keys.public_key_p);
                    $('#elgamalPublicKeyGEncryptInput').val(keys.public_key_g);
                    $('#elgamalPublicKeyYEncryptInput').val(keys.public_key_y);

                    $('#elgamalPublicKeyPDecryptInput').val(keys.public_key_p);
                    $('#elgamalPublicKeyGDecryptInput').val(keys.public_key_g);
                    $('#elgamalPrivateKeyXDecryptInput').val(keys.private_key_x);

                    layer.msg(response.message || 'ElGamal密钥生成成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '密钥生成失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#elgamalGenerateKeysResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false; 
    });

    // --- 2. ElGamal 明文加密 ---
    form.on('submit(elgamalEncryptFilter)', function (formData) {
        var plaintext = $('#elgamalPlaintextEncryptInput').val();
        var publicKeyP = $('#elgamalPublicKeyPEncryptInput').val();
        var publicKeyG = $('#elgamalPublicKeyGEncryptInput').val();
        var publicKeyY = $('#elgamalPublicKeyYEncryptInput').val();

        if (!plaintext || !publicKeyP || !publicKeyG || !publicKeyY) {
            layer.alert('进行加密操作，明文和公钥P, G, Y均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }

        layer.load(1);
        var payload = {
            plaintext: plaintext,
            public_key_p: publicKeyP,
            public_key_g: publicKeyG,
            public_key_y: publicKeyY
        };
        console.log("发送ElGamal加密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/encrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                var resultContainerId = "#elgamalEncryptResultArea"; // 假设的ID
                $(resultContainerId).empty();

                if (response.success && response.ciphertext_c1 && response.ciphertext_c2) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>ElGamal加密结果</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>密文 C1:</strong>\n" + $('<div/>').text(response.ciphertext_c1).html() + "</pre>";
                    resultHtml += "<pre><strong>密文 C2:</strong>\n" + $('<div/>').text(response.ciphertext_c2).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);

                    // 自动填充到解密表单
                    $('#elgamalCiphertextC1DecryptInput').val(response.ciphertext_c1);
                    $('#elgamalCiphertextC2DecryptInput').val(response.ciphertext_c2);

                    layer.msg(response.message || 'ElGamal加密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '加密失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#elgamalEncryptResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });

    // --- 3. ElGamal 密文解密 ---
    form.on('submit(elgamalDecryptFilter)', function (formData) {
        var ciphertextC1 = $('#elgamalCiphertextC1DecryptInput').val();
        var ciphertextC2 = $('#elgamalCiphertextC2DecryptInput').val();
        var publicKeyP = $('#elgamalPublicKeyPDecryptInput').val(); // p for decryption
        var publicKeyG = $('#elgamalPublicKeyGDecryptInput').val(); // g for decryption
        var privateKeyX = $('#elgamalPrivateKeyXDecryptInput').val(); // x for decryption

        if (!ciphertextC1 || !ciphertextC2 || !publicKeyP || !publicKeyG || !privateKeyX) {
            layer.alert('进行解密操作，密文C1, C2, 公开参数P, G 及私钥X均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }
        
        layer.load(1);
        var payload = {
            ciphertext_c1: ciphertextC1,
            ciphertext_c2: ciphertextC2,
            public_key_p_dec: publicKeyP,
            public_key_g_dec: publicKeyG,
            private_key_x_dec: privateKeyX
        };
        console.log("发送ElGamal解密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/decrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                var resultContainerId = "#elgamalDecryptResultArea"; // 假设的ID
                $(resultContainerId).empty();

                if (response.success && response.decrypted_text !== undefined) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>ElGamal解密结果</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>解密后明文:</strong>\n" + $('<div/>').text(response.decrypted_text).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);
                    layer.msg(response.message || 'ElGamal解密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '解密失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#elgamalDecryptResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });
});