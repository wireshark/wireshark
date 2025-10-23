/** @file
 * Filesystem utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Default profile name.
 */
#define DEFAULT_PROFILE      "Default"

/**
 * @brief Initialize our configuration environment.
 *
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.
 * If you change the default application flavor, you should should do
 * so before calling this.
 *
 * @param arg0 Executable name hint. Should be argv[0].
 * @return NULL on success, and a g_mallocated string containing an error on failure.
 */
WS_DLL_PUBLIC char *configuration_init(const char *arg0);

/**
 * @brief Get the directory in which the main (Wireshark, TShark, Stratoshark, etc)
 * program resides.
 *
 * Extcaps should use get_extcap_dir() to get their path.
 *
 * @return The main program file directory.
 */
WS_DLL_PUBLIC const char *get_progfile_dir(void);

/**
 * @brief Given the program name, construct the path name of a non-extcap
 * Wireshark executable file.
 *
 * The executable name doesn't include ".exe";
 * append it on Windows, so that callers don't have to worry about that.
 *
 * This presumes that all non-extcap executables are in the same directory.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 *
 * @param filename The base name of the executable (without extension).
 * @return A g_malloc()'d string containing the full path. Must be g_free()'d by the caller.
 */
WS_DLL_PUBLIC char *get_executable_path(const char *filename);

/**
 * @brief Get the directory in which plugins are stored
 *
 * This must not be called
 * before configuration_init() is called, as they might be stored in a
 * subdirectory of the program file directory.
 *
 * @return A pointer to a statically allocated string containing the plugin directory path.
 */
WS_DLL_PUBLIC const char *get_plugins_dir(void);

/**
 * @brief Append VERSION_MAJOR.VERSION_MINOR to the plugin dir.
 *
 * Constructs the full plugin directory path by appending the current
 * major and minor version numbers to the base plugin directory.
 *
 * @return A pointer to a statically allocated string containing the versioned plugin directory path.
 */
WS_DLL_PUBLIC const char *get_plugins_dir_with_version(void);

/**
 * @brief Gets the personal plugin directory.
 *
 * Returns the path to the user's personal plugin directory.
 *
 * @return A pointer to a statically allocated string containing the personal plugin directory path.
 */
WS_DLL_PUBLIC const char *get_plugins_pers_dir(void);

/**
 * @brief Appends VERSION_MAJOR.VERSION_MINOR to the personal plugin directory path.
 *
 * Constructs the full path to the user's personal plugin directory by appending
 * the current Wireshark major and minor version numbers.
 *
 * @return A pointer to a statically allocated string containing the versioned personal plugin directory path.
 */
WS_DLL_PUBLIC const char *get_plugins_pers_dir_with_version(void);

/**
 * @brief Gets the directory in which extcap hooks are stored.
 *
 * This function returns the path to the extcap hook directory.
 * It must not be called before configuration_init(), as the directory
 * may be located in a subdirectory of the program file directory.
 *
 * @return A pointer to a statically allocated string containing the extcap directory path.
 */
WS_DLL_PUBLIC const char *get_extcap_dir(void);

/**
 * @brief Gets the personal extcap directory.
 *
 * Returns the path to the user's personal extcap directory, typically located
 * within their home or configuration directory.
 *
 * @return A pointer to a statically allocated string containing the personal extcap directory path.
 */
WS_DLL_PUBLIC const char *get_extcap_pers_dir(void);

/**
 * @brief Indicates whether Wireshark is running from a build directory.
 *
 * Returns a boolean flag that signals whether the current execution context
 * is within a build directory.
 *
 * @return true if running from a build directory, false otherwise.
 */
WS_DLL_PUBLIC bool running_in_build_directory(void);

/**
 * @brief Gets the directory in which global configuration files are stored.
 *
 * Returns the path to the directory containing global configuration files,
 * typically shared across all users and installations.
 *
 * @return A pointer to a statically allocated string containing the global configuration directory path.
 */
WS_DLL_PUBLIC const char *get_datafile_dir(void);

/**
 * @brief Constructs the full path to a global configuration file.
 *
 * Given a file name, this function builds the full path to the corresponding
 * global configuration file located in the datafile directory.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free()
 * when no longer needed.
 *
 * @param filename The name of the configuration file.
 * @return A g_malloc()'d string containing the full path to the file.
 */
WS_DLL_PUBLIC char *get_datafile_path(const char *filename);

/**
 * @brief Gets the directory in which global documentation files are stored.
 *
 * Returns the path to the directory containing global documentation files,
 * typically shared across all users and installations.
 *
 * @return A pointer to a statically allocated string containing the documentation directory path.
 */
WS_DLL_PUBLIC const char *get_doc_dir(void);

/**
 * @brief Constructs the full path to a global documentation file.
 *
 * Given a file name, this function builds the full path to the corresponding
 * documentation file located in the global documentation directory.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free()
 * when no longer needed.
 *
 * @param filename The name of the documentation file.
 * @return A g_malloc()'d string containing the full path to the file.
 */
WS_DLL_PUBLIC char *get_docfile_path(const char *filename);

/**
 * @brief Constructs the URL path to a global documentation file.
 *
 * Given a documentation file name, this function builds the corresponding
 * URL path pointing to the global documentation location.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free()
 * when no longer needed.
 *
 * @param filename The name of the documentation file.
 * @return A g_malloc()'d string containing the full URL path to the file.
 */
WS_DLL_PUBLIC char *doc_file_url(const char *filename);

/**
 * @brief Gets the directory in which system files are stored.
 *
 * On UNIX-like systems, this typically refers to standard locations such as "/etc".
 * On Windows, where such directories do not exist, the files are retrieved from
 * the Wireshark global configuration and data file directory instead.
 *
 * @return A pointer to a statically allocated string containing the system file directory path.
 */
WS_DLL_PUBLIC const char *get_systemfile_dir(void);

/**
 * @brief Sets the configuration profile name for storing personal configuration files.
 *
 * This function defines the active profile name, which determines the location
 * where personal configuration files will be stored and accessed.
 *
 * @param profilename The name of the configuration profile to use.
 */
WS_DLL_PUBLIC void set_profile_name(const char *profilename);

/**
 * @brief Gets the current configuration profile name used for storing personal configuration files.
 *
 * Returns the name of the active configuration profile, which determines
 * the location for storing and retrieving personal configuration files.
 *
 * @return A pointer to a statically allocated string containing the profile name.
 */
WS_DLL_PUBLIC const char *get_profile_name(void);

/**
 * @brief Checks whether the current configuration profile is the default profile.
 *
 * Determines if the active profile is the default one, which typically stores
 * user configuration in the standard personal configuration directory.
 *
 * @return true if the current profile is the default profile, false otherwise.
 */
WS_DLL_PUBLIC bool is_default_profile(void);

/**
 * @brief Checks whether global configuration profiles are available.
 *
 * Determines if any global (system-wide) configuration profiles are present
 * and accessible to the application.
 *
 * @return true if global profiles are available, false otherwise.
 */
WS_DLL_PUBLIC bool has_global_profiles(void);

/**
 * @brief Gets the directory used to store configuration profile directories.
 *
 * Returns the path to the base directory where configuration profiles are stored.
 * The caller is responsible for freeing the returned string using g_free().
 *
 * @return A g_malloc()'d string containing the configuration profiles directory path.
 */
WS_DLL_PUBLIC char *get_profiles_dir(void);

/**
 * @brief Gets the directory used to store configuration files for a given profile.
 *
 * Constructs the full path to the configuration directory associated with the specified profile name.
 * If the profile is global, the path will point to the system-wide profile location; otherwise,
 * it will point to the user's personal profile directory.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free() when no longer needed.
 *
 * @param profilename The name of the configuration profile.
 * @param is_global true if the profile is global, false if it is personal.
 * @return A g_malloc()'d string containing the full path to the profile's configuration directory.
 */
WS_DLL_PUBLIC char *get_profile_dir(const char *profilename, bool is_global);

/**
 * @brief Creates the directory used to store configuration profile directories.
 *
 * Ensures that the base directory for storing configuration profiles exists,
 * creating it if necessary. The full path to the created or existing directory
 * is returned via the output parameter.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free()
 * when no longer needed.
 *
 * @param pf_dir_path_return Pointer to a location where the directory path string will be stored.
 * @return 0 on success, or a non-zero error code on failure.
 */
WS_DLL_PUBLIC int create_profiles_dir(char **pf_dir_path_return);

/**
 * @brief Gets the directory used to store global configuration profile directories.
 *
 * Returns the path to the base directory where global (system-wide) configuration profiles are stored.
 * The caller is responsible for freeing the returned string using g_free().
 *
 * @return A g_malloc()'d string containing the global profiles directory path.
 */
WS_DLL_PUBLIC char *get_global_profiles_dir(void);

/**
 * @brief Enables or disables tracking of personal configuration file names for profile duplication.
 *
 * When enabled, this function records the names of personal configuration files
 * that should be copied when duplicating a configuration profile.
 *
 * @param store true to begin storing file names, false to stop.
 */
WS_DLL_PUBLIC void profile_store_persconffiles(bool store);

/**
 * @brief Registers a filename to the personal configuration files storage.
 *
 * Adds a file to the list of personal configuration files that should be tracked
 * for profile duplication. This is intended for files that are not automatically
 * registered via get_persconffile_path() during startup.
 *
 * @param filename The name of the personal configuration file to register.
 */
WS_DLL_PUBLIC void profile_register_persconffile(const char *filename);

/**
 * @brief Checks whether a given configuration profile exists.
 *
 * Determines if the specified configuration profile is present either in the
 * global or personal profile directories.
 *
 * @param profilename The name of the configuration profile to check.
 * @param global true to check in the global profiles directory, false to check in the personal profiles directory.
 * @return true if the profile exists, false otherwise.
 */
WS_DLL_PUBLIC bool profile_exists(const char *profilename, bool global);

/**
 * @brief Creates a directory for the given configuration profile.
 *
 * Attempts to create a directory for the specified configuration profile.
 * If the creation fails, the function returns -1 and sets *pf_dir_path_return
 * to the path of the directory that could not be created. The returned path
 * is allocated with g_malloc() and must be freed with g_free() by the caller.
 * On success, the function returns 0.
 *
 * @param profilename The name of the configuration profile.
 * @param pf_dir_path_return Pointer to receive the g_malloc()'d path of the failed directory, if any.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int create_persconffile_profile(const char *profilename,
				       char **pf_dir_path_return);

/**
 * @brief Returns the list of known profile configuration filenames.
 *
 * Provides access to a hash table containing the set of recognized configuration
 * file names that are associated with user or global profiles. These filenames
 * are used to determine which files should be included when copying or managing
 * configuration profiles.
 *
 * @return A pointer to a constant GHashTable containing the allowed profile configuration filenames.
 */
WS_DLL_PUBLIC const GHashTable *allowed_profile_filenames(void);

/**
 * @brief Deletes the directory for the given configuration profile.
 *
 * Attempts to remove the directory associated with the specified configuration profile.
 * If the deletion fails, the function returns -1 and sets *pf_dir_path_return to the
 * path of the directory that could not be deleted. The returned path is allocated with
 * g_malloc() and must be freed with g_free() by the caller.
 * On success, the function returns 0.
 *
 * @param profilename The name of the configuration profile to delete.
 * @param pf_dir_path_return Pointer to receive the g_malloc()'d path of the failed directory, if any.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int delete_persconffile_profile(const char *profilename,
                                              char **pf_dir_path_return);

/**
 * @brief Renames the directory for the given configuration profile.
 *
 * Attempts to rename the configuration profile directory from the specified source name
 * to the target name. If the operation fails, the function returns -1 and sets
 * *pf_from_dir_path_return and/or *pf_to_dir_path_return to the respective source or
 * destination paths involved in the failure. These strings are allocated with g_malloc()
 * and must be freed with g_free() by the caller.
 * On success, the function returns 0.
 *
 * @param fromname The current name of the configuration profile.
 * @param toname The new name to assign to the configuration profile.
 * @param pf_from_dir_path_return Pointer to receive the g_malloc()'d source directory path if the rename fails.
 * @param pf_to_dir_path_return Pointer to receive the g_malloc()'d destination directory path if the rename fails.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int rename_persconffile_profile(const char *fromname, const char *toname,
				       char **pf_from_dir_path_return,
				       char **pf_to_dir_path_return);

/**
 * @brief Copies configuration files from one profile to another.
 *
 * Transfers all tracked personal configuration files from the source profile to the destination profile.
 * If the copy operation fails, the function returns -1 and sets one or more of the output parameters
 * to indicate the file or directory involved in the failure. These strings are allocated with g_malloc()
 * and must be freed with g_free() by the caller.
 * On success, the function returns 0.
 *
 * @param toname The name of the destination configuration profile.
 * @param fromname The name of the source configuration profile.
 * @param from_global true if the source profile is global, false if it is personal.
 * @param pf_filename_return Pointer to receive the g_malloc()'d name of the file that failed to copy, if any.
 * @param pf_to_dir_path_return Pointer to receive the g_malloc()'d destination directory path, if applicable.
 * @param pf_from_dir_path_return Pointer to receive the g_malloc()'d source directory path, if applicable.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int copy_persconffile_profile(const char *toname, const char *fromname,
				     bool from_global,
				     char **pf_filename_return,
				     char **pf_to_dir_path_return,
				     char **pf_from_dir_path_return);

/**
 * @brief Creates the directory that holds personal configuration files, if necessary.
 *
 * Ensures that the directory used to store personal configuration files exists,
 * creating it if it does not. If the creation fails, the function returns -1 and
 * sets *pf_dir_path_return to the path of the directory that could not be created.
 * The returned string is allocated with g_malloc() and must be freed with g_free()
 * by the caller. On success, the function returns 0.
 *
 * @param pf_dir_path_return Pointer to receive the g_malloc()'d path of the failed directory, if any.
 * @return 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int create_persconffile_dir(char **pf_dir_path_return);

/**
 * @brief Constructs the full path name of a personal configuration file.
 *
 * Builds the absolute path to a personal configuration file based on the provided filename.
 * If configuration profiles are enabled and `from_profile` is true, the path will be constructed
 * within the active profile's directory; otherwise, it will use the standard personal configuration directory.
 *
 * The returned string is allocated with g_malloc() and must be freed with g_free() by the caller.
 *
 * @param filename The name of the configuration file.
 * @param from_profile true to use the profile-specific directory, false to use the default personal config directory.
 * @return A g_malloc()'d string containing the full path to the configuration file.
 */
WS_DLL_PUBLIC char *get_persconffile_path(const char *filename, bool from_profile);

/**
 * @brief Sets the path of the personal configuration file directory.
 *
 * Defines the base directory where personal configuration files will be stored.
 * This overrides any default or previously set location for personal configuration data.
 *
 * @param p The path to use as the personal configuration file directory.
 */
WS_DLL_PUBLIC void set_persconffile_dir(const char *p);

/**
 * @brief Gets the default directory in which personal data is stored.
 *
 * Returns the path to the default location for storing personal data files.
 * On Windows systems, this corresponds to the "My Documents" folder within the user's profile.
 * On UNIX-like systems, this is typically the current working directory.
 *
 * @return A pointer to a statically allocated string containing the personal data directory path.
 */
WS_DLL_PUBLIC const char *get_persdatafile_dir(void);

/**
 * @brief Sets the path of the directory in which personal data is stored.
 *
 * Overrides the default location used for storing personal data files.
 * This allows customization of where personal data is saved, independent of platform defaults.
 *
 * @param p The path to use as the personal data directory.
 */
WS_DLL_PUBLIC void set_persdatafile_dir(const char *p);

/**
 * @brief Gets the current working directory.
 *
 * Returns the absolute path of the process's current working directory.
 * This path reflects where the application is executing and may be used
 * for resolving relative file paths.
 *
 * @return A pointer to a statically allocated string containing the current working directory.
 */
WS_DLL_PUBLIC WS_RETNONNULL const char *get_current_working_dir(void);

/**
 * @brief Returns a human-readable error message for file open or create failures.
 *
 * Converts a UNIX-style errno value into a descriptive error message suitable for
 * reporting issues encountered during file open or create operations.
 *
 * @param err The errno value indicating the specific error.
 * @param for_writing true if the operation was a write (create) attempt, false if it was a read (open) attempt.
 * @return A pointer to a statically allocated string describing the error.
 */
WS_DLL_PUBLIC const char *file_open_error_message(int err, bool for_writing);

/**
 * @brief Returns a human-readable error message for write operation failures.
 *
 * Converts a UNIX-style errno value into a descriptive error message suitable for
 * reporting issues encountered during file write operations.
 *
 * @param err The errno value indicating the specific write error.
 * @return A pointer to a statically allocated string describing the error.
 */
WS_DLL_PUBLIC const char *file_write_error_message(int err);

/**
 * @brief Returns the last component of a pathname.
 *
 * Extracts the final segment of the given path, typically representing the filename
 * or directory name at the end of the path. This does not modify the input string.
 *
 * @param path The full path from which to extract the basename.
 * @return A pointer to the last component of the pathname.
 */
WS_DLL_PUBLIC const char *get_basename(const char *path);

/**
 * @brief Returns a pointer to the last pathname separator in a given path.
 *
 * Scans the provided pathname and returns a pointer to the last pathname separator
 * character (e.g., '/' or '\\' depending on platform). If the pathname contains no
 * separators, the function returns NULL.
 *
 * @param path The pathname to scan.
 * @return A pointer to the last pathname separator character, or NULL if none is found.
 */
WS_DLL_PUBLIC char *find_last_pathname_separator(const char *path);

/**
 * @brief Returns the directory portion of a pathname.
 *
 * Extracts all components of the given pathname except the last one (typically the file or final directory name).
 * This function modifies the input string in-place to truncate it at the last pathname separator.
 *
 * @note The input pathname is overwritten. If the original value is needed later, make a copy before calling.
 *
 * @param path A modifiable string containing the full path.
 * @return A pointer to the modified input string containing the directory portion.
 */
WS_DLL_PUBLIC char *get_dirname(char *path);

/**
 * @brief Tests whether a given pathname refers to a directory.
 *
 * Performs a stat() system call on the provided pathname and returns:
 * - The errno value if the stat() call fails.
 * - EISDIR if the stat() call succeeds and the pathname refers to a directory.
 * - 0 if the stat() call succeeds and the pathname refers to a non-directory file.
 *
 * This function is useful for distinguishing between files and directories,
 * and for detecting stat-related errors.
 *
 * @param path The path to test.
 * @return errno on stat failure, EISDIR if it's a directory, or 0 if it's a non-directory file.
 */
WS_DLL_PUBLIC int test_for_directory(const char *path);

/**
 * @brief Tests whether a given pathname refers to a FIFO (named pipe).
 *
 * Performs a stat() system call on the provided pathname and returns:
 * - The errno value if the stat() call fails.
 * - ESPIPE if the stat() call succeeds and the pathname refers to a FIFO.
 * - 0 if the stat() call succeeds and the pathname refers to a non-FIFO file.
 *
 * This function is useful for identifying named pipes and handling them appropriately
 * in file or stream operations.
 *
 * @param path The path to test.
 * @return errno on stat failure, ESPIPE if it's a FIFO, or 0 if it's a non-FIFO file.
 */
WS_DLL_PUBLIC int test_for_fifo(const char *path);

/**
 * @brief Tests whether a given pathname refers to a regular file.
 *
 * Performs a stat() system call on the provided pathname and returns true if the call
 * succeeds and the file is a regular file. Symbolic links to regular files are also
 * considered valid, as stat() follows links.
 *
 * @param path The path to test.
 * @return true if the pathname refers to a regular file or a symlink to one, false otherwise.
 */
WS_DLL_PUBLIC bool test_for_regular_file(const char *path);

/**
 * @brief Checks whether a file exists.
 *
 * Determines if the file specified by the given pathname exists and is accessible.
 * This check typically relies on file system metadata and does not open the file.
 *
 * @param fname The pathname of the file to check.
 * @return true if the file exists, false otherwise.
 */
WS_DLL_PUBLIC bool file_exists(const char *fname);

/**
 * @brief Checks if a configuration file exists and contains non-comment entries.
 *
 * Verifies that the specified file exists and includes at least one line of text
 * that does not begin with the given comment character. This is useful for detecting
 * meaningful configuration content while ignoring commented-out lines.
 *
 * @param fname The pathname of the configuration file to check.
 * @param comment_char The character used to denote comments (e.g., '#').
 * @return true if the file exists and contains at least one non-comment line, false otherwise.
 */
WS_DLL_PUBLIC bool config_file_exists_with_entries(const char *fname, char comment_char);

/**
 * @brief Checks whether two filenames refer to the same file.
 *
 * Compares two file paths to determine if they resolve to the same file,
 * accounting for both absolute and relative path representations. This typically
 * involves resolving symbolic links and canonicalizing paths before comparison.
 *
 * @param fname1 The first file path to compare.
 * @param fname2 The second file path to compare.
 * @return true if both paths refer to the same file, false otherwise.
 */
WS_DLL_PUBLIC bool files_identical(const char *fname1, const char *fname2);

/**
 * @brief Checks whether a file has been recreated since it was opened.
 *
 * Compares the current metadata of the file at the given pathname with the metadata
 * of the file descriptor to determine if the file has been replaced or recreated.
 * This is useful for detecting log rotation or external file updates that may require
 * reopening the file to access the new content.
 *
 * @param fd The file descriptor of the originally opened file.
 * @param filename The pathname of the file to compare against.
 * @return true if the file has been recreated and needs to be reopened, false otherwise.
 */
WS_DLL_PUBLIC bool file_needs_reopen(int fd, const char* filename);

/**
 * @brief Writes raw content to a file in binary mode.
 *
 * Writes the specified content to the given file using binary mode, ensuring compatibility
 * across platforms that differentiate between text and binary file handling. This function
 * does not interpret or modify the content—it writes the raw bytes as-is.
 *
 * If the write operation fails, the function returns false and displays a simple dialog
 * window with the corresponding error message. On success, it returns true.
 *
 * @param filename The path to the file to write.
 * @param content A pointer to the raw content to be written.
 * @param content_len The number of bytes to write from the content buffer.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool write_file_binary_mode(const char *filename,
    const void *content, size_t content_len);

/**
 * @brief Copies a file using binary mode.
 *
 * Performs a byte-for-byte copy of the source file to the destination file using binary mode.
 * This ensures compatibility across platforms that distinguish between text and binary file handling.
 * The function does not interpret or modify the content—it copies the raw bytes as-is.
 *
 * If the copy operation fails, the function returns false and displays a simple dialog window
 * with the corresponding error message. On success, it returns true.
 *
 * @param from_filename The path to the source file to copy.
 * @param to_filename The path to the destination file.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool copy_file_binary_mode(const char *from_filename,
    const char *to_filename);


/**
 * @brief Constructs a filesystem URL from a given filename.
 *
 * Converts the specified filename into a filesystem URL. If the filename is a relative path,
 * it is automatically prefixed with the datafile directory path to form an absolute reference.
 * This is useful for generating standardized URLs for accessing local resources.
 *
 * @param filename A file name or path. Relative paths will be prefixed with the datafile directory path.
 * @return A newly allocated string containing the filesystem URL, or NULL on failure.
 *         The returned string must be freed using g_free().
 */
WS_DLL_PUBLIC char* data_file_url(const char *filename);

/**
 * @brief Frees internal program directory structures.
 *
 * Releases any memory or resources allocated for managing program directory paths.
 * This function should be called during cleanup to avoid memory leaks related to
 * internal directory tracking.
 */
WS_DLL_PUBLIC void free_progdirs(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILESYSTEM_H */
