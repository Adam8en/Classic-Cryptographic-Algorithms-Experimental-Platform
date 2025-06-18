// app/static/js/ecc_logic.js

layui.use(['form', 'layer', 'jquery'], function () {
    var form = layui.form;
    var layer = layui.layer;
    var $ = layui.jquery;

    var API_BASE_URL = '/api/ecc'; // 确保与后端API路由匹配

    // --- 1. ECC 密钥生成 ---
    form.on('submit(eccGenerateKeysFilter)', function (formData) {
        layer.load(1);
        
        // 从下拉框获取选择的曲线名称
        var curveName = $('#ecc-curve-select-generate').val();
        if (!curveName) {
            layer.alert('请选择一条椭圆曲线！', {icon: 7});
            layer.closeAll('loading');
            return false;
        }

        var payload = {
            curve_name: curveName
        };
        console.log("发送ECC密钥生成请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/generate_keys',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                var resultContainerId = "#eccGenerateKeysResultArea";
                $(resultContainerId).empty();

                if (response.success && response.keys) {
                    var keys = response.keys;
                    var resultHtml = "<fieldset class='layui-elem-field' style='margin-top: 15px;'><legend>生成的ECC密钥 ("+keys.curve_name+")</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>私钥 d (整数):</strong>\n" + $('<div/>').text(keys.private_key_d).html() + "</pre>";
                    resultHtml += "<pre><strong>公钥 Qx (点坐标):</strong>\n" + $('<div/>').text(keys.public_key_qx).html() + "</pre>";
                    resultHtml += "<pre><strong>公钥 Qy (点坐标):</strong>\n" + $('<div/>').text(keys.public_key_qy).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);

                    // 自动填充到加密和解密表单
                    $('#eccPublicKeyQxEncryptInput').val(keys.public_key_qx);
                    $('#eccPublicKeyQyEncryptInput').val(keys.public_key_qy);
                    $('#eccPrivateKeyDDecryptInput').val(keys.private_key_d);
                    // 将曲线名称也传递下去，可以放在一个隐藏输入或只读文本框中
                    $('#eccCurveNameEncryptInput').val(keys.curve_name);
                    $('#eccCurveNameDecryptInput').val(keys.curve_name);

                    layer.msg(response.message || 'ECC密钥生成成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '密钥生成失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#eccGenerateKeysResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });

    // --- 2. ECC 明文加密 (简化ECIES) ---
    form.on('submit(eccEncryptFilter)', function (formData) {
        var plaintext = $('#eccPlaintextEncryptInput').val();
        var publicKeyQx = $('#eccPublicKeyQxEncryptInput').val();
        var publicKeyQy = $('#eccPublicKeyQyEncryptInput').val();
        // 获取当前操作的曲线名称
        var curveName = $('#eccCurveNameEncryptInput').val();

        if (!plaintext || !publicKeyQx || !publicKeyQy || !curveName) {
            layer.alert('进行加密操作，明文、接收方公钥Qx、Qy以及曲线名称均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }

        layer.load(1);
        var payload = {
            plaintext: plaintext,
            public_key_qx: publicKeyQx,
            public_key_qy: publicKeyQy,
            curve_name: curveName // 在请求中加入曲线名称
        };
        console.log("发送ECC加密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/encrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                var resultContainerId = "#eccEncryptResultArea";
                $(resultContainerId).empty();

                if (response.success && response.ephemeral_R_x && response.ciphertext_hex) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>ECC加密结果 ("+response.curve_name+")</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>临时公钥 R.x:</strong>\n" + $('<div/>').text(response.ephemeral_R_x).html() + "</pre>";
                    resultHtml += "<pre><strong>临时公钥 R.y:</strong>\n" + $('<div/>').text(response.ephemeral_R_y).html() + "</pre>";
                    resultHtml += "<pre><strong>密文 C (Hex):</strong>\n" + $('<div/>').text(response.ciphertext_hex).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);

                    // 自动填充到解密表单
                    $('#eccEphemeralRxDecryptInput').val(response.ephemeral_R_x);
                    $('#eccEphemeralRyDecryptInput').val(response.ephemeral_R_y);
                    $('#eccCiphertextHexDecryptInput').val(response.ciphertext_hex);
                    // 同时填充曲线名称
                    $('#eccCurveNameDecryptInput').val(response.curve_name);

                    layer.msg(response.message || 'ECC加密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '加密失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#eccEncryptResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });

    // --- 3. ECC 密文解密 (简化ECIES) ---
    form.on('submit(eccDecryptFilter)', function (formData) {
        var ephemeralRx = $('#eccEphemeralRxDecryptInput').val();
        var ephemeralRy = $('#eccEphemeralRyDecryptInput').val();
        var ciphertextHex = $('#eccCiphertextHexDecryptInput').val();
        var privateKeyD = $('#eccPrivateKeyDDecryptInput').val();
        // 获取当前操作的曲线名称
        var curveName = $('#eccCurveNameDecryptInput').val();


        if (!ephemeralRx || !ephemeralRy || !ciphertextHex || !privateKeyD || !curveName) {
            layer.alert('进行解密操作，临时公钥R(x,y), 密文, 私钥d以及曲线名称均不能为空！', { icon: 7, title: '输入错误' });
            return false;
        }
        
        layer.load(1);
        var payload = {
            ephemeral_R_x: ephemeralRx,
            ephemeral_R_y: ephemeralRy,
            ciphertext_hex: ciphertextHex,
            private_key_d: privateKeyD,
            curve_name: curveName // 在请求中加入曲线名称
        };
        console.log("发送ECC解密请求:", payload);

        $.ajax({
            url: API_BASE_URL + '/decrypt',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(payload),
            success: function (response) {
                layer.closeAll('loading');
                var resultContainerId = "#eccDecryptResultArea";
                $(resultContainerId).empty();

                if (response.success && response.decrypted_text !== undefined) {
                    var resultHtml = "<fieldset class='layui-elem-field'><legend>ECC解密结果 ("+curveName+")</legend><div class='layui-field-box'>";
                    resultHtml += "<pre><strong>解密后明文:</strong>\n" + $('<div/>').text(response.decrypted_text).html() + "</pre>";
                    resultHtml += "</div></fieldset>";
                    $(resultContainerId).html(resultHtml);
                    layer.msg(response.message || 'ECC解密成功！', { icon: 1, time: 2000 });
                } else {
                    var errorDetail = response.message || '解密失败。';
                    $(resultContainerId).html("<p class='error-message'>错误: " + $('<div/>').text(errorDetail).html() + "</p>");
                    layer.alert(errorDetail, { icon: 2, title: '操作失败' });
                }
            },
            error: function (xhr) {
                layer.closeAll('loading');
                var resultContainerId = "#eccDecryptResultArea";
                $(resultContainerId).empty();
                var errorMsg = xhr.responseJSON ? xhr.responseJSON.message : '请求错误。';
                $(resultContainerId).html("<p class='error-message'>请求错误: " + $('<div/>').text(errorMsg).html() + "</p>");
                layer.alert('错误: ' + errorMsg, { icon: 2, title: '请求错误' });
            }
        });
        return false;
    });
});