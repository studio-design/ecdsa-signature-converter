<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__.'/src',
        __DIR__.'/tests',
    ]);

return (new PhpCsFixer\Config)
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS2.0'       => true,
        '@PER-CS2.0:risky' => true,

        // Strict
        'declare_strict_types' => true,
        'strict_param'         => true,

        // Imports
        'global_namespace_import' => [
            'import_classes'   => true,
            'import_constants' => false,
            'import_functions' => false,
        ],
        'no_unused_imports'       => true,
        'ordered_imports'         => ['sort_algorithm' => 'alpha'],

        // Clean-up
        'no_extra_blank_lines' => [
            'tokens' => [
                'curly_brace_block',
                'extra',
                'parenthesis_brace_block',
                'square_brace_block',
                'throw',
                'use',
            ],
        ],
        'no_trailing_comma_in_singleline' => true,
        'no_whitespace_in_blank_line'     => true,
        'single_blank_line_at_eof'        => true,
        'trim_array_spaces'               => true,

        // PHPDoc
        'no_empty_phpdoc'                       => true,
        'phpdoc_trim'                           => true,
        'phpdoc_align'                          => ['align' => 'vertical'],
        'phpdoc_separation'                     => true,
        'phpdoc_single_line_var_spacing'        => true,
        'no_superfluous_phpdoc_tags'            => ['remove_inheritdoc' => true],

        // Misc
        'array_syntax'  => ['syntax' => 'short'],
        'binary_operator_spaces' => [
            'default'   => 'single_space',
            'operators' => ['=>' => 'align_single_space_minimal'],
        ],
        'concat_space'  => ['spacing' => 'none'],
        'trailing_comma_in_multiline' => ['elements' => ['arguments', 'arrays', 'parameters']],
    ])
    ->setFinder($finder);
