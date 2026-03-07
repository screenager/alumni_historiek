<?php
declare(strict_types=1);

/**
 * Build and download a standalone ZIP of this project on demand.
 * Excludes VCS/editor/macOS artifacts and original_poster source files.
 */

$root = __DIR__;
$versionParam = isset($_GET['version']) ? (string) $_GET['version'] : '';
if (preg_match('/^\d+$/', $versionParam) === 1) {
    $zipName = 'alumni_historiek_postcards' . $versionParam . '.zip';
} else {
    $zipName = 'alumni_historiek_standalone.zip';
}
$tmpZip = tempnam(sys_get_temp_dir(), 'alumni_hist_');

if ($tmpZip === false) {
    http_response_code(500);
    echo 'Could not create temporary file.';
    exit;
}

$zipPath = $tmpZip . '.zip';
@unlink($tmpZip);

if (!class_exists('ZipArchive')) {
    http_response_code(500);
    echo 'ZipArchive extension is not available.';
    exit;
}

function shouldExclude(string $relativePath): bool
{
    $relativePath = str_replace('\\', '/', ltrim($relativePath, '/'));
    $base = basename($relativePath);

    if ($relativePath === '.git' || str_starts_with($relativePath, '.git/')) {
        return true;
    }
    if ($relativePath === '.idea' || str_starts_with($relativePath, '.idea/')) {
        return true;
    }
    if ($relativePath === '__MACOSX' || str_starts_with($relativePath, '__MACOSX/')) {
        return true;
    }
    if ($base === '.DS_Store') {
        return true;
    }
    if ($base === 'alumni_historiek_standalone.zip') {
        return true;
    }
    if (preg_match('/^original_poster/i', $base) === 1) {
        return true;
    }

    return false;
}

$zip = new ZipArchive();
if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    http_response_code(500);
    echo 'Could not create ZIP archive.';
    exit;
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

foreach ($iterator as $fileInfo) {
    $absolutePath = $fileInfo->getPathname();
    $relativePath = substr($absolutePath, strlen($root) + 1);
    if ($relativePath === false || $relativePath === '') {
        continue;
    }

    if (shouldExclude($relativePath)) {
        continue;
    }

    if ($fileInfo->isDir()) {
        $zip->addEmptyDir(str_replace('\\', '/', $relativePath));
        continue;
    }

    if ($fileInfo->isFile()) {
        $zip->addFile($absolutePath, str_replace('\\', '/', $relativePath));
    }
}

$zip->close();

if (!is_file($zipPath)) {
    http_response_code(500);
    echo 'ZIP file was not generated.';
    exit;
}

header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="' . $zipName . '"');
header('Content-Length: ' . filesize($zipPath));
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
readfile($zipPath);
@unlink($zipPath);
exit;
