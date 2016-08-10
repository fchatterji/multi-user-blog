function like(event) {

    var like_button = '#like_button_'.concat(event.data.post_key_url)
    var likes = '#likes_'.concat(event.data.post_key_url)

    $.ajax({
        type: 'POST',
        data: {
            post_key_url: event.data.post_key_url
        },
        url: '/blog/like',

        success: function(data) {

            data = JSON.parse(data)

            $(likes).html(data['likes']);

            if (data['is_liked'] === true) {
                $(like_button).addClass("btn-info");
                $(like_button).removeClass("btn-disabled");

            } else {
                $(like_button).addClass("btn-disabled");
                $(like_button).removeClass("btn-info");
            }
        }
    });
};

