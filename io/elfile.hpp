/**
 * @file
 * @ingroup io
 * @brief file i/o opject with support for zip and gzip files
 */

#ifndef	_ELFILE_HPP_
#define	_ELFILE_HPP_

#include <stdint.h>
#include <sys/stat.h>
#include "zipfilesystem.hpp"

const int_fast32_t max_mem_block_buffer_size = 0x40000; // 256kb

class el_file
{
	private:

		/**
		 * @brief File position.
		 *
		 * The position in the file.
		 */
		int_fast32_t position;

		/**
		 * @brief Memory buffer.
		 *
		 * Memory buffer of the file data.
		 */
		memory_buffer memory;

		/**
		 * @brief Tries to open the file in a zip file.
		 *
		 * Tries to open the file in a zip file. Returns true if successful or false if file is
		 * not found in the zip file system.
		 * @param file_name The name of the file to open.
		 * @param uncompress Flag indicating if the file should get uncompressed.
		 * @param zfile_system The zip file system where to search for the file.
		 */
		bool open_zip(const std::string& file_name, bool compressed,
			zip_file_system& zfile_system);

		/**
		 * @brief Tries to open the file and uncompress it.
		 *
		 * Tries to open the file and uncompress it.
		 * @param file_name The name of the file to open.
		 */
		void open_gzip(const std::string& file_name);

		/**
		 * @brief Tries to open the file and don't uncompress it.
		 *
		 * Tries to open the file and don't uncompress it.
		 * @param file_name The name of the file to open.
		 */
		void open(const std::string& file_name);

	public:

		/**
		 * @brief Opens a file.
		 *
		 * Opens a file read only in binary mode.
		 * @param file_name The name of the file to open.
		 * @param uncompress Flag indicating if the file should get uncompressed.
		 * @param zfile_system The zip file system where to search for the file.
		 */
		el_file(const std::string& file_name, bool uncompress,
			zip_file_system& zfile_system);

		/**
		 * @brief Reads data from the file.
		 *
		 * Reads data from the file.
		 * @param size The number of bytes to read.
		 * @param buffer The buffer for the read data.
		 * @return Returns the number of read bytes.
		 */
		inline int_fast32_t read(int_fast32_t count, void* buffer)
		{
			count = std::max(std::min(count, get_size() - position), 0L);
			memcpy(buffer, memory.get_memory(position), count);
			position += count;

			return count;
		}

		/**
		 * @brief Sets the position in the file.
		 *
		 * Sets the position in the file. If seek_type is SEEK_SET, the new position is offset. If
		 * seek_type is SEEK_CUR, the new position is the old position plus the offset. If
		 * seek_type is SEEK_END, the new position is the file size minus the offset.
		 * @param offset The value used for the calculation for the new position.
		 * @param seek_type The type of seek. Can only be SEEK_SET, SEEK_END or SEEK_CUR.
		 * @return Returns the new position in the file.
		 */
		inline int_fast32_t seek(int_fast32_t offset, int_fast32_t seek_type)
		{
			int_fast32_t pos;

			switch (seek_type)
			{
				case SEEK_SET:
					pos = offset;
					break;
				case SEEK_END:
					pos = get_size() - offset;
					break;
				case SEEK_CUR:
					pos = position + offset;
					break;
				default:
					return -1;
			}
			if ((pos < 0) || (pos > get_size()))
			{
				return -1;
			}
			else
			{
				position = pos;
				return position;
			}
		}

		/**
		 * @brief Gets the position in the file.
		 *
		 * Gets the position in the file.
		 * @return Returns the position in the file.
		 */
		inline int_fast32_t tell() const
		{
			return position;
		}

		/**
		 * @brief Gets the size of the file.
		 *
		 * Gets the size of the file.
		 * @return Returns the size of the file.
		 */
		inline int_fast32_t get_size() const
		{
			return memory.get_size();
		}

		/**
		 * @brief Gets a pointer to the file data.
		 *
		 * Gets the memory pointer of the file data.
		 * @return Returns a memory pointer to the file data.
		 */
		inline void* get_pointer() const
		{
			return memory.get_memory();
		}

		/**
		 * @brief Check if a file exists.
		 *
		 * Check if the given file exists.
		 * @param file_name The name of the file.
		 * @param zfile_system The zip file system to use.
		 * @return Returns true if the file exists, else false.
		 */
		static bool file_exists(const std::string& file_name, const zip_file_system&
			zfile_system);
};

#endif	// _ELFILE_HPP_