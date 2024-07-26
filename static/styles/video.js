document.addEventListener('DOMContentLoaded', function() {
    const bubble = document.getElementById('bubble');
    const videoContainer = document.getElementById('videoContainer');
    const closeBtn = document.getElementById('closeBtn');
    const video = document.getElementById('video');

    function adjustVideoContainerSize() {
        const videoAspectRatio = video.videoWidth / video.videoHeight;
        const containerMaxWidth = window.innerWidth * 0.8; // 80% of window width
        const containerMaxHeight = window.innerHeight * 0.8; // 80% of window height

        let containerWidth = containerMaxWidth;
        let containerHeight = containerWidth / videoAspectRatio;

        if (containerHeight > containerMaxHeight) {
            containerHeight = containerMaxHeight;
            containerWidth = containerHeight * videoAspectRatio;
        }

        videoContainer.style.width = `${containerWidth}px`;
        videoContainer.style.height = `${containerHeight}px`;
    }

    bubble.addEventListener('click', () => {
        if (videoContainer.style.display === 'block') {
            videoContainer.style.display = 'none';
            video.pause();
            video.currentTime = 0;
        } else {
            videoContainer.style.display = 'block';
            video.play();
            adjustVideoContainerSize();
        }
    });

    closeBtn.addEventListener('click', () => {
        videoContainer.style.display = 'none';
        video.pause();
        video.currentTime = 0;
    });

    video.addEventListener('loadedmetadata', adjustVideoContainerSize);
    window.addEventListener('resize', adjustVideoContainerSize);
});
