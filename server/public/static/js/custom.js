$(function () {

    $(document).ajaxStart(function(){
        $("#wait").attr("style", "display: flex !important");
    });

    $(document).ajaxComplete(function(){
        $("#wait").attr("style", "display: none !important");
    });

    $(function () {
        $('[data-toggle="tooltip"]').tooltip()
    })

    $('.truncate').succinct({
        size: 120
    });

    setInterval(function(){
        $.ajax({
            url: "/user/refresh",
            method: "POST"
        })
    }, 5*60*1000);

    var getFilename = function(jqXHR) {
        var disposition = jqXHR.getResponseHeader("Content-Disposition");

        if (disposition && disposition.indexOf("attachment") !== -1) {
            var filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
            var matches = filenameRegex.exec(disposition);
            if (matches != null && matches[1]) {
                return matches[1].replace(/['"]/g, "");
            }
        }

        return "";
    }

    var showAlert = function(context, alert) {
        $(".alert").removeClass("alert-empty alert-danger alert-info").addClass("alert-" + context);
        $(".alert .message").html(alert);
        $("html, body").animate({ scrollTop: 0 }, "fast");
    }

    var toggleActions = function(context) {
        $(context).toggleClass("disabled");
        if (!$(context).is(".play")) {
            $(context).siblings().toggleClass("disabled");
        }
        else if ($(context).is(".last")) {
            $(context).siblings(".disabled").not(".play").toggleClass("disabled");
        }
    }

    $("a.action").click(function(e) {
        var isCustom = $(this).attr("data-method");
        var isDisabled = $(this).is("a.disabled");

        if (isCustom || isDisabled) {
            e.preventDefault();
        }

        if (isCustom && !isDisabled) {
            $.ajax({
                url: $(this).attr('href'),
                method: $(this).attr("data-method"),
                context: $(this),
                dataType: $(this).attr("data-type") ? "binary" : "json",
                contentType: $(this).data("payload") ? "application/json" : undefined,
                data: $(this).data("payload") ? $(this).data("payload") : undefined,
                statusCode: {
                    401: function() {
                        setTimeout(function() {
                            window.location.href = "/user/login";
                        }, 1000*2)
                    }
                },
            }).done(function(data, textStatus, jqXHR ) {
                if (data.hasOwnProperty("context") && data.hasOwnProperty("alert")) {
                    showAlert(data.context, data.alert);
                    if (data.context.includes("success")) {
                        toggleActions(this);
                        if ($(this).is("a.plot")) {
                            var context = $(this);
                            setTimeout(function() {
                                window.location.href = context.attr('href');
                            }, 1000*5);
                        } else if ($(this).is("a.verify") || $(this).is("a.play") || $(this).is("a.delete")) {
                            setTimeout(function() {
                                location.reload()
                            }, 1000*5);
                        }
                    }
                } else {
                    var blob = new Blob([data], {type: jqXHR.getResponseHeader("Content-Type")});
                    var URL = window.URL || window.webkitURL;
                    var downloadUrl = URL.createObjectURL(blob);

                    var filename = getFilename(jqXHR);
                    if (filename) {
                        var a = document.createElement("a");
                        a.href = downloadUrl;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                    } else {
                        window.location = downloadUrl;
                    }

                    setTimeout(function () { URL.revokeObjectURL(downloadUrl); }, 100);
                }
            }).fail(function(jqXHR, textStatus) {
                showAlert("danger", "You are not logged in. Please log in and try again.");
            });
        }
    });

    $(".close").on("click", function() {
        $(".alert").toggleClass("alert-empty");
    });

    $("#accordion .collapse").on('hide.bs.collapse', function (e) {
        $("#"+e.target.id).parent().animate({"padding-top": 0, "padding-bottom": 0});
    })

    $("#accordion .collapse").on('show.bs.collapse', function (e) {
        $("#"+e.target.id).parent().animate({"padding": "1.25rem"})
    })

    if ($("#plots").length) {
        setInterval(function() {
            $.post(window.location.href, function(data) {});
        }, 1000*30);
        setInterval(function() {
            location.reload();
        }, 1000*100);
    }

    if ($("#analysis").length) {
        var guid = $("#analysis").attr("data-job-guid");
        var selectedBucket = "";

        var renderBuckets = function(buckets) {
            $("#analysisBuckets").empty();
            if (!buckets || buckets.length === 0) {
                $("#analysisBuckets").append('<div class="list-group-item text-body-secondary">No results yet.</div>');
                return;
            }
            buckets.forEach(function(b) {
                var item = $('<a href="#" class="list-group-item list-group-item-action"></a>');
                item.text(b);
                item.on("click", function(e) {
                    e.preventDefault();
                    selectedBucket = b;
                    $("#analysisBucketTitle").text(" / " + b);
                    loadFiles(b);
                });
                $("#analysisBuckets").append(item);
            });
        };

        var renderFiles = function(files) {
            $("#analysisFiles").empty();
            if (!files || files.length === 0) {
                $("#analysisFiles").append('<div class="list-group-item text-body-secondary">No files.</div>');
                return;
            }
            files.forEach(function(f) {
                var row = $('<div class="list-group-item d-flex justify-content-between align-items-center"></div>');
                var left = $('<a href="#" class="me-2 flex-grow-1"></a>');
                left.text(f);
                left.on("click", function(e) {
                    e.preventDefault();
                    readReport(selectedBucket, f);
                });

                // file_root == crash hash (per your script)
                var hash = f;

                var btns = $('<div class="btn-group"></div>');
                var dl = $('<a class="btn btn-outline-secondary action download" data-type="binary" data-method="POST" href="/job/' + guid + '/analysis_download_crash"></a>');
                dl.append('<svg class="bi bi-download" width="18" height="18" fill="currentColor" viewBox="0 0 20 20"><use xlink:href="/static/svg/bootstrap-icons.svg#download"/></svg>');
                dl.data("payload", JSON.stringify({hash: hash}));

                var del = $('<a class="btn btn-outline-secondary action delete" data-method="POST" href="/job/' + guid + '/analysis_delete"></a>');
                del.append('<svg class="bi bi-trash-fill" width="18" height="18" fill="currentColor" viewBox="0 0 20 20"><use xlink:href="/static/svg/bootstrap-icons.svg#trash-fill"/></svg>');
                del.data("payload", JSON.stringify({bucket: selectedBucket, file: f}));

                btns.append(dl).append(del);

                row.append(left).append(btns);
                $("#analysisFiles").append(row);
            });
        };

        var loadBuckets = function() {
            $.ajax({
                url: "/job/" + guid + "/analysis_buckets",
                method: "POST",
                dataType: "json",
            }).done(function(data) {
                renderBuckets(data.buckets || []);
            });
        };

        var loadFiles = function(bucket) {
            $.ajax({
                url: "/job/" + guid + "/analysis_files",
                method: "POST",
                dataType: "json",
                data: JSON.stringify({bucket: bucket}),
                contentType: "application/json",
            }).done(function(data) {
                renderFiles(data.files || []);
            });
        };

        var readReport = function(bucket, file) {
            $.ajax({
                url: "/job/" + guid + "/analysis_read",
                method: "POST",
                dataType: "json",
                data: JSON.stringify({bucket: bucket, file: file}),
                contentType: "application/json",
            }).done(function(data) {
                $("#analysisModalTitle").text(bucket + " / " + file);
                $("#analysisModalBody").text(data.text || "");
                var m = new bootstrap.Modal(document.getElementById("analysisModal"));
                m.show();
            });
        };

        loadBuckets();
    }

    $("form.create").submit(function(e) {
        e.preventDefault();

        $.ajax({
            url: $(this).attr("action"),
            method: "PUT",
            data: $(this).serialize(),
            context: $(this),
        }).done(function(data) {
            showAlert(data.context, data.alert);
        });
    });

    $("#autoresume").change(function() {
        if($(this).is(":checked")) {
            $("#skipCrashes").prop("checked", true);
        }
    });

    $('#cards').masonry({
        itemSelector: '.col'
    }).on('shown.bs.collapse hidden.bs.collapse', function() {
        $('#cards').masonry();
    });

});

$.ajaxTransport("+binary", function(options, originalOptions, jqXHR) {
    var isBinary = options.dataType && options.dataType == "binary",
        isBlob = options.data && window.Blob && options.data instanceof Blob,
        isArrayBuffer = options.data && window.ArrayBuffer && options.data instanceof ArrayBuffer;
    if (window.FormData && (isBinary || isArrayBuffer || isBlob)) {
        return {
            send: function(headers, callback) {
                var xhr = new XMLHttpRequest(),
                    url = options.url,
                    type = options.type,
                    async = options.async || true,
                    dataType = options.responseType || "blob",
                    data = options.data || null;

                xhr.addEventListener("load", function() {
                    var data = {};
                    data[options.dataType] = xhr.response;
                    callback(xhr.status, xhr.statusText, data, xhr.getAllResponseHeaders());
                });

                xhr.open(type, url, async);
                xhr.responseType = dataType;
                xhr.send(data);
            },
            abort: function() {
                jqXHR.abort();
            }
        };
    }
});

jQuery.expr[':'].contains = function(a, i, m) {
    return jQuery(a).text().toUpperCase().indexOf(m[3].toUpperCase()) >= 0;
};

var filterCards = function() {
    $('#cards').find('.col').removeClass('d-none');
    var filter = $("#search").val();
    if (filter) {
        $('#cards').find('.card .card-body:not(:contains("'+filter+'"))').parent().parent().parent().addClass('d-none');
        $('#cards').masonry();
    }
}

$(window).on('load', function() {
    filterCards();
})

$('#search').on('keyup', function() {
    filterCards();
})
