<?php
defined('ABSPATH') || exit;

get_header();
?>
<main id="alumni-historiek-content" class="alumni-historiek-content">
    <?php echo alumni_historiek_get_public_body_html(); ?>
</main>
<?php
get_footer();
